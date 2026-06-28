package checks

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── JWT-verifying test server ────────────────────────────────────────────────

// jwtTestServer verifies HS256 tokens against verifySecret and optionally
// accepts alg:none (the vulnerable behavior).
type jwtTestServer struct {
	verifySecret  string
	acceptAlgNone bool
}

func (s *jwtTestServer) verify(authHeader string) bool {
	tok := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	hb, err := b64uDecode(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]interface{}
	if json.Unmarshal(hb, &hdr) != nil {
		return false
	}
	alg, _ := hdr["alg"].(string)
	if strings.EqualFold(alg, "none") {
		return s.acceptAlgNone
	}
	if isHMAC(alg) {
		expected, ok := hmacSign(parts[0]+"."+parts[1], s.verifySecret, alg)
		return ok && hmac.Equal([]byte(expected), []byte(parts[2]))
	}
	return false
}

func (s *jwtTestServer) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.verify(r.Header.Get("Authorization")) {
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"errors":[{"message":"Unauthorized"}]}`)
}

// genuineJWT builds a valid HS256 token signed with secret.
func genuineJWT(secret string, withExp bool) string {
	payload := map[string]interface{}{"sub": "user-123", "role": "user"}
	if withExp {
		payload["exp"] = float64(time.Now().Add(time.Hour).Unix())
	}
	return buildJWT(map[string]interface{}{}, payload, secret, "HS256")
}

func jwtContext(url, token string) *CheckContext {
	return &CheckContext{Target: url, Headers: map[string]string{"Authorization": "Bearer " + token}}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestJWT_AlgNoneAccepted(t *testing.T) {
	strong := "strong-secret-not-in-any-wordlist-9f8a7b6c5d"
	srv := httptest.NewServer(http.HandlerFunc((&jwtTestServer{verifySecret: strong, acceptAlgNone: true}).handler))
	defer srv.Close()

	genuine := genuineJWT(strong, true)
	res, err := (&jwtWeaknessCheck{}).Run(t.Context(), jwtContext(srv.URL, genuine))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization || f.CWE != "CWE-347" || f.OWASP != "API2:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" || !strings.Contains(f.Title, "alg:none") {
		t.Fatalf("expected confirmed alg:none finding, got %q / %q", f.Confidence, f.Title)
	}
	// The genuine token must never appear in the finding.
	if strings.Contains(f.Description, genuine) || strings.Contains(string(f.ReproBody), genuine) {
		t.Fatal("genuine JWT leaked into the finding")
	}
	if res.ProbeCount > 16 {
		t.Fatalf("probe count exceeded the bound: %d", res.ProbeCount)
	}
}

func TestJWT_WeakSecret(t *testing.T) {
	// The server uses the weak secret "secret"; the genuine token is signed with it.
	srv := httptest.NewServer(http.HandlerFunc((&jwtTestServer{verifySecret: "secret", acceptAlgNone: false}).handler))
	defer srv.Close()

	genuine := genuineJWT("secret", true)
	res, err := (&jwtWeaknessCheck{}).Run(t.Context(), jwtContext(srv.URL, genuine))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if !strings.Contains(f.Title, "weak HMAC secret") || f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed weak-secret finding, got %q / %q", f.Title, f.Confidence)
	}
	if !strings.Contains(f.Description, `"secret"`) {
		t.Fatalf("description should name the recovered secret: %s", f.Description)
	}
}

func TestJWT_MissingExp(t *testing.T) {
	strong := "strong-secret-not-in-any-wordlist-9f8a7b6c5d"
	srv := httptest.NewServer(http.HandlerFunc((&jwtTestServer{verifySecret: strong, acceptAlgNone: false}).handler))
	defer srv.Close()

	genuine := genuineJWT(strong, false) // no exp claim
	res, err := (&jwtWeaknessCheck{}).Run(t.Context(), jwtContext(srv.URL, genuine))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (missing exp), got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if !strings.Contains(f.Title, "missing exp") || f.Confidence != "firm" {
		t.Fatalf("expected firm missing-exp finding, got %q / %q", f.Title, f.Confidence)
	}
}

func TestJWT_SecureRejectsAll(t *testing.T) {
	strong := "strong-secret-not-in-any-wordlist-9f8a7b6c5d"
	srv := httptest.NewServer(http.HandlerFunc((&jwtTestServer{verifySecret: strong, acceptAlgNone: false}).handler))
	defer srv.Close()

	genuine := genuineJWT(strong, true)
	res, err := (&jwtWeaknessCheck{}).Run(t.Context(), jwtContext(srv.URL, genuine))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings against a correctly-verifying server, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
	if res.ProbeCount > 16 {
		t.Fatalf("probe count exceeded the bound: %d", res.ProbeCount)
	}
}

func TestJWT_NonJWTSkipped(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", Headers: map[string]string{"Authorization": "Bearer not-a-jwt"}}
	res, err := (&jwtWeaknessCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}
