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

// newAuthzTestCmd is like newTestCmd but also registers the authz flags.
func newAuthzTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan"}
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
	cmd.Flags().StringArray("identity", nil, "")
	cmd.Flags().Bool("authz-allow-mutations", false, "")
	return cmd
}

func TestParseIdentityFlag(t *testing.T) {
	ic, err := parseIdentityFlag("name=userA;priv=10;tenant=t1;header=Authorization: Bearer XYZ;header=X-Tenant: t1")
	require.NoError(t, err)
	assert.Equal(t, "userA", ic.Name)
	assert.Equal(t, 10, ic.Privilege)
	assert.Equal(t, "t1", ic.Tenant)
	assert.Equal(t, "Bearer XYZ", ic.Headers["Authorization"])
	assert.Equal(t, "t1", ic.Headers["X-Tenant"])
}

func TestParseIdentityFlag_Errors(t *testing.T) {
	for _, raw := range []string{
		"priv=10",                   // missing name
		"name=a;priv=notanumber",    // bad privilege
		"name=a;header=NoColonHere", // bad header
		"name=a;bogus=1",            // unknown key
		"name=a;justakey",           // no '='
	} {
		if _, err := parseIdentityFlag(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestLoad_IdentityFlags(t *testing.T) {
	cmd := newAuthzTestCmd()
	require.NoError(t, cmd.Flags().Set("identity", "name=admin;priv=100;header=Authorization: Bearer A"))
	require.NoError(t, cmd.Flags().Set("identity", "name=userB;priv=10;header=Authorization: Bearer B"))
	require.NoError(t, cmd.Flags().Set("authz-allow-mutations", "true"))

	cfg, err := Load(viper.New(), cmd)
	require.NoError(t, err)

	require.Len(t, cfg.Identities, 2)
	assert.Equal(t, "admin", cfg.Identities[0].Name)
	assert.Equal(t, 100, cfg.Identities[0].Privilege)
	assert.Equal(t, "userB", cfg.Identities[1].Name)
	assert.True(t, cfg.AllowAuthzMutations)
}

func TestLoad_IdentitiesFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gqls.yaml")
	yaml := `url: http://from-file
allow_authz_mutations: true
identities:
  - name: admin
    privilege: 100
    tenant: t1
    headers:
      Authorization: "Bearer FILE"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))

	cmd := newAuthzTestCmd()
	require.NoError(t, cmd.Flags().Set("config", cfgPath))

	cfg, err := Load(viper.New(), cmd)
	require.NoError(t, err)

	require.Len(t, cfg.Identities, 1)
	assert.Equal(t, "admin", cfg.Identities[0].Name)
	assert.Equal(t, "t1", cfg.Identities[0].Tenant)
	assert.Equal(t, "Bearer FILE", cfg.Identities[0].Headers["Authorization"])
	assert.True(t, cfg.AllowAuthzMutations)
}

func TestLoad_IdentityFlagOverridesFileByName(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gqls.yaml")
	yaml := `identities:
  - name: admin
    privilege: 1
    headers:
      Authorization: "Bearer FILE"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))

	cmd := newAuthzTestCmd()
	require.NoError(t, cmd.Flags().Set("config", cfgPath))
	require.NoError(t, cmd.Flags().Set("identity", "name=admin;priv=100;header=Authorization: Bearer FLAG"))

	cfg, err := Load(viper.New(), cmd)
	require.NoError(t, err)

	require.Len(t, cfg.Identities, 1, "same-name identity should be deduped")
	assert.Equal(t, 100, cfg.Identities[0].Privilege, "CLI flag should win over file")
	assert.Equal(t, "Bearer FLAG", cfg.Identities[0].Headers["Authorization"])
}

func TestResolveIdentityHeaders_ExpandsEnv(t *testing.T) {
	t.Setenv("GQLS_TEST_TOKEN", "sekret")
	ic := IdentityConfig{Headers: map[string]string{"Authorization": "Bearer ${GQLS_TEST_TOKEN}"}}
	got := ResolveIdentityHeaders(ic)
	assert.Equal(t, "Bearer sekret", got["Authorization"])
}
