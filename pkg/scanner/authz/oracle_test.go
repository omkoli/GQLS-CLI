package authz

import (
	"testing"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func resp(status int, body string) *transport.Response {
	return &transport.Response{StatusCode: status, Body: []byte(body)}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   *transport.Response
		want Class
	}{
		{"nil", nil, ClassUnknown},
		{"401", resp(401, ``), ClassAuthDenied},
		{"403", resp(403, ``), ClassAuthDenied},
		{"429", resp(429, ``), ClassRateLimited},
		{"500", resp(500, `boom`), ClassServerError},
		{"success", resp(200, `{"data":{"user":{"id":"1"}}}`), ClassSuccess},
		{"auth error code", resp(200, `{"data":null,"errors":[{"message":"nope","extensions":{"code":"FORBIDDEN"}}]}`), ClassAuthDenied},
		{"auth error message", resp(200, `{"errors":[{"message":"You are not authorized"}]}`), ClassAuthDenied},
		{"auth wins over data", resp(200, `{"data":{"user":{"id":"1"}},"errors":[{"message":"forbidden"}]}`), ClassAuthDenied},
		{"rate limit message", resp(200, `{"errors":[{"message":"rate limit exceeded"}]}`), ClassRateLimited},
		{"validation", resp(200, `{"errors":[{"message":"Cannot query field foo on type Query"}]}`), ClassValidation},
		{"validation code", resp(200, `{"errors":[{"message":"x","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`), ClassValidation},
		{"not found", resp(200, `{"errors":[{"message":"User does not exist"}]}`), ClassNotFound},
		{"empty data", resp(200, `{"data":null}`), ClassEmpty},
		{"malformed", resp(200, `<html>oops`), ClassUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.in); got != c.want {
				t.Fatalf("Classify(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestClassify_NeverPanics(t *testing.T) {
	for _, body := range []string{``, `{`, `null`, `{"data":}`, `[1,2,3]`} {
		_ = Classify(resp(200, body))
	}
}

func TestCompare_SameObjectLeak(t *testing.T) {
	owner := resp(200, `{"data":{"user":{"id":"42","email":"victim@x.com"}}}`)
	attacker := resp(200, `{"data":{"user":{"id":"42","email":"victim@x.com"}}}`)
	d := Compare(owner, attacker, "data.user.id")
	if !d.SameObject {
		t.Fatalf("expected SameObject=true (attacker got owner's id 42)")
	}
	if d.OwnerClass != ClassSuccess || d.AttackerClass != ClassSuccess {
		t.Fatalf("expected both Success, got owner=%v attacker=%v", d.OwnerClass, d.AttackerClass)
	}
}

func TestCompare_AttackerDenied(t *testing.T) {
	owner := resp(200, `{"data":{"user":{"id":"42"}}}`)
	attacker := resp(403, `{"errors":[{"message":"forbidden"}]}`)
	d := Compare(owner, attacker, "data.user.id")
	if d.SameObject {
		t.Fatalf("expected SameObject=false when attacker denied")
	}
	if d.AttackerClass != ClassAuthDenied {
		t.Fatalf("expected AttackerClass=AuthDenied, got %v", d.AttackerClass)
	}
}

func TestCompare_AttackerOwnDifferentObject(t *testing.T) {
	owner := resp(200, `{"data":{"user":{"id":"42"}}}`)
	attacker := resp(200, `{"data":{"user":{"id":"99"}}}`) // attacker's own object
	d := Compare(owner, attacker, "data.user.id")
	if d.SameObject {
		t.Fatalf("expected SameObject=false when ids differ")
	}
}

func TestCompare_FallbackIDLeaf(t *testing.T) {
	// idPath does not resolve directly; fallback id-leaf search should match.
	owner := resp(200, `{"data":{"order":{"id":"7"}}}`)
	attacker := resp(200, `{"data":{"order":{"id":"7"}}}`)
	d := Compare(owner, attacker, "data.user.id")
	if !d.SameObject {
		t.Fatalf("expected fallback id-leaf to detect same object id=7")
	}
}
