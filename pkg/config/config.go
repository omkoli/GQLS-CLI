// Package config loads and validates scan configuration from files, env vars, and CLI flags.
package config

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ScanConfig holds the complete configuration for a single scan run.
type ScanConfig struct {
	// TargetURL is the GraphQL endpoint to scan.
	TargetURL string `mapstructure:"url"`
	// Headers are HTTP headers sent with every request; values may reference ${ENV_VAR}.
	Headers map[string]string `mapstructure:"headers"`
	// Checks is the allow-list of check IDs to run; empty means run all.
	Checks []string `mapstructure:"checks"`
	// SkipChecks is the deny-list of check IDs to exclude.
	SkipChecks []string `mapstructure:"skip_checks"`
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration `mapstructure:"timeout"`
	// RateLimit is the maximum number of requests per second.
	RateLimit int `mapstructure:"rate_limit"`
	// OutputFormat is one of "terminal", "json", or "sarif".
	OutputFormat string `mapstructure:"output_format"`
	// OutputFile is the file path for output; empty means stdout.
	OutputFile string `mapstructure:"output_file"`
	// FailOn is the minimum severity level that causes exit code 1.
	FailOn string `mapstructure:"fail_on"`
	// FalsePositives is a list of finding fingerprints to suppress.
	FalsePositives []string `mapstructure:"false_positives"`
	// NoColor disables ANSI color codes in terminal output.
	NoColor bool `mapstructure:"no_color"`
	// Identities are the operator-supplied principals used for stateful
	// authorization testing (BOLA/BFLA/BOPLA/cross-tenant). Each carries its own
	// headers; header values may reference ${ENV_VAR}.
	Identities []IdentityConfig `mapstructure:"identities"`
	// AllowAuthzMutations gates authorization checks that perform state-changing
	// requests (e.g. GQL-A05). It defaults to false.
	AllowAuthzMutations bool `mapstructure:"allow_authz_mutations"`
	// AllowedMutations is the explicit per-name allow-list of mutations that
	// GQL-A05 may invoke even when their name looks destructive
	// (delete/remove/...). Empty means no destructive mutation is ever invoked.
	AllowedMutations []string `mapstructure:"allowed_authz_mutations"`
	// AuthzSeeds maps a root object-fetcher field name to a known object id owned
	// by a privileged identity, used to seed object-level authz tests (GQL-A01).
	// When absent for a fetcher, the check attempts to self-discover an id.
	AuthzSeeds map[string]string `mapstructure:"authz_seeds"`

	// CurlBody is the raw request body extracted from a --curl / --curl-file
	// input. It is not loaded from config files or environment variables; it
	// is populated at runtime by the scan command after parsing the curl
	// command. Checks that perform active injection (e.g. GQL-011) use this
	// as the seed request body.
	CurlBody string `mapstructure:"-"`
}

// IdentityConfig describes a single operator-supplied principal for
// authorization testing. Headers (typically an Authorization bearer token and
// an optional tenant header) may reference ${ENV_VAR} expressions.
type IdentityConfig struct {
	// Name is the operator-chosen label, e.g. "admin", "userA".
	Name string `mapstructure:"name"`
	// Privilege ranks the identity; higher is more privileged. Anonymous is 0.
	Privilege int `mapstructure:"privilege"`
	// Tenant is an optional tenant/org identifier for cross-tenant checks.
	Tenant string `mapstructure:"tenant"`
	// Headers are the HTTP headers carried by this identity.
	Headers map[string]string `mapstructure:"headers"`
}

// Load reads configuration applying precedence: config file < env vars < CLI flags.
// The viper instance v should be freshly created to avoid cross-test pollution.
func Load(v *viper.Viper, cmd *cobra.Command) (*ScanConfig, error) {
	// 1. Defaults
	v.SetDefault("timeout", 30*time.Second)
	v.SetDefault("rate_limit", 10)
	v.SetDefault("output_format", "terminal")
	v.SetDefault("fail_on", "HIGH")
	v.SetDefault("no_color", false)

	// 2. Config file (lowest precedence)
	cfgFile := ""
	if fl := cmd.Flags().Lookup("config"); fl != nil {
		cfgFile = fl.Value.String()
	}
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("gqls")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.gqls")
	}
	if err := v.ReadInConfig(); err != nil {
		if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
			if cfgFile != "" {
				return nil, err
			}
		}
	}

	// 3. Environment variables (middle precedence — AutomaticEnv picks these up
	//    automatically after SetEnvPrefix).
	v.SetEnvPrefix("GQLS")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Explicit env bindings for nested keys that AutomaticEnv may miss.
	_ = v.BindEnv("url", "GQLS_URL")
	_ = v.BindEnv("output_format", "GQLS_OUTPUT_FORMAT")
	_ = v.BindEnv("output_file", "GQLS_OUTPUT_FILE")
	_ = v.BindEnv("fail_on", "GQLS_FAIL_ON")
	_ = v.BindEnv("no_color", "GQLS_NO_COLOR")
	_ = v.BindEnv("timeout", "GQLS_TIMEOUT")
	_ = v.BindEnv("rate_limit", "GQLS_RATE_LIMIT")
	_ = v.BindEnv("allow_authz_mutations", "GQLS_ALLOW_AUTHZ_MUTATIONS")

	// 4. CLI flags (highest precedence)
	bindFlag(v, cmd, "url", "url")
	bindFlag(v, cmd, "output_format", "output")
	bindFlag(v, cmd, "output_file", "output-file")
	bindFlag(v, cmd, "fail_on", "fail-on")
	bindFlag(v, cmd, "no_color", "no-color")
	bindFlag(v, cmd, "timeout", "timeout")
	bindFlag(v, cmd, "rate_limit", "rate-limit")
	bindFlag(v, cmd, "allow_authz_mutations", "authz-allow-mutations")

	cfg := &ScanConfig{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// --header is a string-slice flag that cannot round-trip cleanly through viper.
	if fl := cmd.Flags().Lookup("header"); fl != nil {
		raw, err := cmd.Flags().GetStringArray("header")
		if err == nil && len(raw) > 0 {
			if cfg.Headers == nil {
				cfg.Headers = make(map[string]string)
			}
			for _, h := range raw {
				k, val, found := strings.Cut(h, ":")
				if found {
					cfg.Headers[strings.TrimSpace(k)] = strings.TrimSpace(val)
				}
			}
		}
	}

	// --checks and --skip-checks
	if fl := cmd.Flags().Lookup("checks"); fl != nil {
		if vals, err := cmd.Flags().GetStringArray("checks"); err == nil && len(vals) > 0 {
			cfg.Checks = vals
		}
	}
	if fl := cmd.Flags().Lookup("skip-checks"); fl != nil {
		if vals, err := cmd.Flags().GetStringArray("skip-checks"); err == nil && len(vals) > 0 {
			cfg.SkipChecks = vals
		}
	}

	// --identity is a string-slice flag that cannot round-trip through viper.
	// Each value is appended to any identities loaded from the config file;
	// later entries (CLI) override earlier ones (file) with the same name.
	if fl := cmd.Flags().Lookup("identity"); fl != nil {
		if vals, err := cmd.Flags().GetStringArray("identity"); err == nil && len(vals) > 0 {
			for _, raw := range vals {
				ic, perr := parseIdentityFlag(raw)
				if perr != nil {
					return nil, perr
				}
				cfg.Identities = append(cfg.Identities, ic)
			}
		}
	}
	// Viper lowercases config-file map keys; canonicalize header names from both
	// the config file and the flags so lookups like Headers["Authorization"] are
	// predictable regardless of source. (HTTP headers are case-insensitive, but a
	// stable map case keeps callers simple.)
	canonicalizeIdentityHeaders(cfg.Identities)
	cfg.Identities = dedupeIdentities(cfg.Identities)

	// --authz-allow-mutation is a string-slice flag naming individual mutations
	// GQL-A05 may invoke even if their name looks destructive. Flag values are
	// appended to any from the config file.
	if fl := cmd.Flags().Lookup("authz-allow-mutation"); fl != nil {
		if vals, err := cmd.Flags().GetStringArray("authz-allow-mutation"); err == nil && len(vals) > 0 {
			cfg.AllowedMutations = append(cfg.AllowedMutations, vals...)
		}
	}

	// --authz-seed is a string-slice flag (e.g. 'user.id=42' or 'user=42') that
	// seeds known object ids for object-level authz tests. Flag values are merged
	// over any seeds from the config file.
	if fl := cmd.Flags().Lookup("authz-seed"); fl != nil {
		if vals, err := cmd.Flags().GetStringArray("authz-seed"); err == nil && len(vals) > 0 {
			if cfg.AuthzSeeds == nil {
				cfg.AuthzSeeds = make(map[string]string, len(vals))
			}
			for _, raw := range vals {
				field, value, perr := parseSeedFlag(raw)
				if perr != nil {
					return nil, perr
				}
				cfg.AuthzSeeds[field] = value
			}
		}
	}

	return cfg, nil
}

// parseSeedFlag parses a single --authz-seed value of the form 'field=value' or
// 'field.idArg=value' (e.g. 'user.id=42'), returning the fetcher field name and
// the seed id value.
func parseSeedFlag(raw string) (field, value string, err error) {
	key, val, found := strings.Cut(raw, "=")
	if !found {
		return "", "", fmt.Errorf("invalid --authz-seed %q (expected field=value)", raw)
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	if key == "" || val == "" {
		return "", "", fmt.Errorf("invalid --authz-seed %q (field and value are required)", raw)
	}
	// Accept 'field.idArg' by keeping only the leading field segment.
	if dot := strings.IndexByte(key, '.'); dot >= 0 {
		key = key[:dot]
	}
	if key == "" {
		return "", "", fmt.Errorf("invalid --authz-seed %q (empty field)", raw)
	}
	return key, val, nil
}

// canonicalizeIdentityHeaders rewrites each identity's header keys to their HTTP
// canonical form (e.g. "authorization" → "Authorization") in place.
func canonicalizeIdentityHeaders(ids []IdentityConfig) {
	for i := range ids {
		if len(ids[i].Headers) == 0 {
			continue
		}
		canon := make(map[string]string, len(ids[i].Headers))
		for k, v := range ids[i].Headers {
			canon[http.CanonicalHeaderKey(k)] = v
		}
		ids[i].Headers = canon
	}
}

// parseIdentityFlag parses a single --identity value of the form
//
//	name=userA;priv=10;tenant=t1;header=Authorization: Bearer X;header=X-Tenant: t1
//
// Segments are separated by ';'. Each segment is a key=value pair; the value of
// a repeated 'header' segment is split on the first ':' into a header name/value.
func parseIdentityFlag(raw string) (IdentityConfig, error) {
	ic := IdentityConfig{Headers: map[string]string{}}
	for _, seg := range strings.Split(raw, ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		key, val, found := strings.Cut(seg, "=")
		if !found {
			return IdentityConfig{}, fmt.Errorf("invalid --identity segment %q (expected key=value)", seg)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "name":
			ic.Name = val
		case "priv", "privilege":
			n, err := strconv.Atoi(val)
			if err != nil {
				return IdentityConfig{}, fmt.Errorf("invalid --identity privilege %q: %w", val, err)
			}
			ic.Privilege = n
		case "tenant":
			ic.Tenant = val
		case "header":
			hk, hv, ok := strings.Cut(val, ":")
			if !ok {
				return IdentityConfig{}, fmt.Errorf("invalid --identity header %q (expected 'Name: Value')", val)
			}
			ic.Headers[strings.TrimSpace(hk)] = strings.TrimSpace(hv)
		default:
			return IdentityConfig{}, fmt.Errorf("unknown --identity key %q", key)
		}
	}
	if ic.Name == "" {
		return IdentityConfig{}, fmt.Errorf("--identity requires a name= segment")
	}
	return ic, nil
}

// dedupeIdentities removes identities with duplicate names, keeping the last
// occurrence (so CLI flags, appended after config-file entries, win).
func dedupeIdentities(in []IdentityConfig) []IdentityConfig {
	if len(in) < 2 {
		return in
	}
	lastIdx := map[string]int{}
	for i, ic := range in {
		lastIdx[ic.Name] = i
	}
	var out []IdentityConfig
	for i, ic := range in {
		if lastIdx[ic.Name] == i {
			out = append(out, ic)
		}
	}
	return out
}

// ResolveIdentityHeaders returns a copy of an identity's headers with
// ${ENV_VAR} expressions expanded.
func ResolveIdentityHeaders(ic IdentityConfig) map[string]string {
	resolved := make(map[string]string, len(ic.Headers))
	for k, v := range ic.Headers {
		resolved[k] = os.Expand(v, os.Getenv)
	}
	return resolved
}

// ResolveHeaders returns a copy of cfg.Headers with ${ENV_VAR} expressions expanded.
func (cfg *ScanConfig) ResolveHeaders() map[string]string {
	resolved := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		resolved[k] = os.Expand(v, os.Getenv)
	}
	return resolved
}

// bindFlag binds a Cobra flag to a Viper key when the flag is registered on cmd.
func bindFlag(v *viper.Viper, cmd *cobra.Command, viperKey, flagName string) {
	if fl := cmd.Flags().Lookup(flagName); fl != nil {
		_ = v.BindPFlag(viperKey, fl)
	}
}
