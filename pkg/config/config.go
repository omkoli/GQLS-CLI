// Package config loads and validates scan configuration from files, env vars, and CLI flags.
package config

import (
	"os"
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

	// CurlBody is the raw request body extracted from a --curl / --curl-file
	// input. It is not loaded from config files or environment variables; it
	// is populated at runtime by the scan command after parsing the curl
	// command. Checks that perform active injection (e.g. GQL-011) use this
	// as the seed request body.
	CurlBody string `mapstructure:"-"`
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

	// 4. CLI flags (highest precedence)
	bindFlag(v, cmd, "url", "url")
	bindFlag(v, cmd, "output_format", "output")
	bindFlag(v, cmd, "output_file", "output-file")
	bindFlag(v, cmd, "fail_on", "fail-on")
	bindFlag(v, cmd, "no_color", "no-color")
	bindFlag(v, cmd, "timeout", "timeout")
	bindFlag(v, cmd, "rate_limit", "rate-limit")

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

	return cfg, nil
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
