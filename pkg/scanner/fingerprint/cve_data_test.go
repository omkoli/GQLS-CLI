package fingerprint

import (
	"net/http"
	"testing"
	"time"
)

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		// Apollo Server CSRF range.
		{"2.25.3", ">=2.0.0 <2.25.4", true},
		{"2.25.4", ">=2.0.0 <2.25.4", false}, // patched
		{"1.9.9", ">=2.0.0 <2.25.4", false},  // below range
		{"2.0.0", ">=2.0.0 <2.25.4", true},   // inclusive lower bound
		// graphql-js DoS range.
		{"16.5.0", ">=16.3.0 <16.8.1", true},
		{"16.8.1", ">=16.3.0 <16.8.1", false}, // exclusive upper bound (fixed)
		{"16.8", ">=16.3.0 <16.8.1", true},    // partial version → 16.8.0
		// Hasura exact-match range.
		{"1.3.3", "=1.3.3", true},
		{"1.3.4", "=1.3.3", false},
		{"1.3.2", "=1.3.3", false},
		// HotChocolate multi-branch OR range.
		{"11.0.0", "<12.22.7 || >=13.0.0 <13.9.16 || >=14.0.0 <14.3.1 || >=15.0.0 <15.1.14", true},
		{"13.5.0", "<12.22.7 || >=13.0.0 <13.9.16 || >=14.0.0 <14.3.1 || >=15.0.0 <15.1.14", true},
		{"12.22.7", "<12.22.7 || >=13.0.0 <13.9.16", false}, // patched in branch 12
		{"14.3.1", ">=14.0.0 <14.3.1 || >=15.0.0 <15.1.14", false},
		{"15.1.14", ">=15.0.0 <15.1.14", false},
		// graphql-ruby multi-branch OR range (subset).
		{"2.1.10", ">=1.11.5 <1.11.11 || >=2.1.0 <2.1.15", true},
		{"2.1.15", ">=1.11.5 <1.11.11 || >=2.1.0 <2.1.15", false},
		{"3.0.0", ">=1.11.5 <1.11.11 || >=2.1.0 <2.1.15", false},
		// Tolerances: v-prefix and pre-release metadata.
		{"v2.25.3", ">=2.0.0 <2.25.4", true},
		{"2.25.3-beta", ">=2.0.0 <2.25.4", true},
		{"2.25.3+build.7", ">=2.0.0 <2.25.4", true},
	}
	for _, c := range cases {
		got, err := VersionInRange(c.version, c.constraint)
		if err != nil {
			t.Errorf("VersionInRange(%q, %q) unexpected error: %v", c.version, c.constraint, err)
			continue
		}
		if got != c.want {
			t.Errorf("VersionInRange(%q, %q) = %v, want %v", c.version, c.constraint, got, c.want)
		}
	}
}

func TestVersionInRange_Errors(t *testing.T) {
	if _, err := VersionInRange("not-a-version", ">=1.0.0"); err == nil {
		t.Error("expected error for unparseable version")
	}
	if _, err := VersionInRange("1.0.0", "garbage~~"); err == nil {
		t.Error("expected error for unparseable constraint")
	}
}

func TestValidateVersionRange(t *testing.T) {
	valid := []string{
		">=1.0.0 <2.0.0",
		"=1.3.3",
		"1.2.3",
		">1.0.0 || <0.5.0",
		"<=3.4.5",
		"<12.22.7 || >=13.0.0 <13.9.16",
	}
	for _, v := range valid {
		if err := ValidateVersionRange(v); err != nil {
			t.Errorf("ValidateVersionRange(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",
		"   ",
		">=abc",
		">=1.0.0 <",
		"~>1.2.3",
		">=1.2.3.4.5",
		"||",
	}
	for _, v := range invalid {
		if err := ValidateVersionRange(v); err == nil {
			t.Errorf("ValidateVersionRange(%q) = nil, want error", v)
		}
	}
}

func TestVersionFromHeaders(t *testing.T) {
	t.Run("server banner with engine token", func(t *testing.T) {
		h := http.Header{}
		h.Set("Server", "Apollo Server/2.25.3")
		v, src := VersionFromHeaders("Apollo Server", h)
		if v != "2.25.3" || src != "Server" {
			t.Fatalf("got (%q,%q), want (2.25.3, Server)", v, src)
		}
	})

	t.Run("x-powered-by banner", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Powered-By", "graphql-ruby 2.0.30")
		v, _ := VersionFromHeaders("graphql-ruby", h)
		if v != "2.0.30" {
			t.Fatalf("got %q, want 2.0.30", v)
		}
	})

	t.Run("unrelated component version is not attributed", func(t *testing.T) {
		h := http.Header{}
		h.Set("Server", "nginx/1.21.0")
		if v, _ := VersionFromHeaders("Apollo Server", h); v != "" {
			t.Fatalf("nginx version must not be attributed to the engine, got %q", v)
		}
	})

	t.Run("nil headers and unknown engine", func(t *testing.T) {
		if v, _ := VersionFromHeaders("Apollo Server", nil); v != "" {
			t.Fatalf("nil headers should yield no version, got %q", v)
		}
		h := http.Header{}
		h.Set("Server", "SomeEngine/9.9.9")
		if v, _ := VersionFromHeaders("engine-with-no-tokens", h); v != "" {
			t.Fatalf("engine with no tokens should yield no version, got %q", v)
		}
	})
}

func TestAdvisories_Lookup(t *testing.T) {
	if got := Advisories("nonexistent-engine"); got != nil {
		t.Fatalf("Advisories(unknown) = %v, want nil", got)
	}
	apollo := Advisories("Apollo Server")
	if len(apollo) == 0 {
		t.Fatal("expected at least one Apollo Server advisory")
	}
	// Returned slice must be a copy (mutating it must not affect the table).
	apollo[0].ID = "MUTATED"
	if Advisories("Apollo Server")[0].ID == "MUTATED" {
		t.Fatal("Advisories must return a defensive copy")
	}
}

// Every advisory's Engine field must equal its map key, so Advisories(engine)
// is consistent with the table layout.
func TestAdvisoryKeysMatchEngineField(t *testing.T) {
	for key, list := range advisories {
		for _, a := range list {
			if a.Engine != key {
				t.Errorf("advisory %s: map key %q != Engine field %q", a.ID, key, a.Engine)
			}
		}
	}
}

// Defense-in-depth duplicate of the check-package integrity test, local to the data.
func TestAllAdvisories_Dated(t *testing.T) {
	for _, a := range AllAdvisories() {
		if _, err := time.Parse("2006-01-02", a.VerifiedOn); err != nil {
			t.Errorf("%s: VerifiedOn %q not a valid date", a.ID, a.VerifiedOn)
		}
		if err := ValidateVersionRange(a.VersionRange); err != nil {
			t.Errorf("%s: VersionRange %q unparseable: %v", a.ID, a.VersionRange, err)
		}
	}
}
