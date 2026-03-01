package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCmd builds a minimal cobra command with all scan flags registered,
// mirroring the flags added in cmd/gqls/scan.go.
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "")
	cmd.Flags().StringArray("header", nil, "")
	cmd.Flags().StringArray("checks", nil, "")
	cmd.Flags().StringArray("skip-checks", nil, "")
	cmd.Flags().String("output", "terminal", "")
	cmd.Flags().String("output-file", "", "")
	cmd.Flags().String("fail-on", "HIGH", "")
	cmd.Flags().Bool("no-color", false, "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().Int("rate-limit", 10, "")
	cmd.Flags().String("config", "", "")
	return cmd
}

func TestLoad_MissingConfigFileDoesNotError(t *testing.T) {
	cmd := newTestCmd()
	v := viper.New()
	cfg, err := Load(v, cmd)
	require.NoError(t, err)
	assert.Equal(t, "terminal", cfg.OutputFormat)
	assert.Equal(t, "HIGH", cfg.FailOn)
	assert.Equal(t, 10, cfg.RateLimit)
}

func TestLoad_FlagOverridesFileValue(t *testing.T) {
	// Write a temporary config file with a URL value.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gqls.yaml")
	err := os.WriteFile(cfgPath, []byte("url: http://from-file\nfail_on: LOW\n"), 0o600)
	require.NoError(t, err)

	cmd := newTestCmd()
	// Set the --config flag to point at our file.
	require.NoError(t, cmd.Flags().Set("config", cfgPath))
	// Override with a CLI flag value.
	require.NoError(t, cmd.Flags().Set("url", "http://from-flag"))
	require.NoError(t, cmd.Flags().Set("fail-on", "CRITICAL"))

	v := viper.New()
	cfg, err := Load(v, cmd)
	require.NoError(t, err)

	assert.Equal(t, "http://from-flag", cfg.TargetURL, "CLI flag should win over file")
	assert.Equal(t, "CRITICAL", cfg.FailOn, "CLI flag should win over file")
}

func TestLoad_EnvVarOverridesFileValue(t *testing.T) {
	// Write a temporary config file.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gqls.yaml")
	err := os.WriteFile(cfgPath, []byte("url: http://from-file\n"), 0o600)
	require.NoError(t, err)

	t.Setenv("GQLS_URL", "http://from-env")

	cmd := newTestCmd()
	require.NoError(t, cmd.Flags().Set("config", cfgPath))

	v := viper.New()
	cfg, err := Load(v, cmd)
	require.NoError(t, err)

	assert.Equal(t, "http://from-env", cfg.TargetURL, "env var should win over file")
}

func TestLoad_FailOnNoneIsPreserved(t *testing.T) {
	cmd := newTestCmd()
	require.NoError(t, cmd.Flags().Set("fail-on", "none"))

	v := viper.New()
	cfg, err := Load(v, cmd)
	require.NoError(t, err)

	assert.Equal(t, "none", cfg.FailOn, "fail-on=none should be stored as-is so callers can detect it")
}

func TestResolveHeaders_ExpandsEnvVars(t *testing.T) {
	t.Setenv("TEST_TOKEN", "secret-value")

	cfg := &ScanConfig{
		Headers: map[string]string{
			"Authorization": "Bearer ${TEST_TOKEN}",
			"X-Static":      "plain",
		},
	}

	resolved := cfg.ResolveHeaders()
	assert.Equal(t, "Bearer secret-value", resolved["Authorization"])
	assert.Equal(t, "plain", resolved["X-Static"])
}

func TestResolveHeaders_EmptyConfig(t *testing.T) {
	cfg := &ScanConfig{}
	resolved := cfg.ResolveHeaders()
	assert.Empty(t, resolved)
}

func TestLoad_Defaults(t *testing.T) {
	cmd := newTestCmd()
	v := viper.New()
	cfg, err := Load(v, cmd)
	require.NoError(t, err)

	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, 10, cfg.RateLimit)
	assert.Equal(t, "terminal", cfg.OutputFormat)
	assert.Equal(t, "HIGH", cfg.FailOn)
	assert.False(t, cfg.NoColor)
}
