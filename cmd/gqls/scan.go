package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gqls-cli/gqls/pkg/config"
	curlparser "github.com/gqls-cli/gqls/pkg/ingest/curl"
	"github.com/gqls-cli/gqls/pkg/reporter"
	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/checks"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// failOnThresholdError is returned by runScan when the --fail-on severity
// threshold is met. It signals main() to exit with code 1 without printing
// an error message (the report already explains the situation).
type failOnThresholdError struct{}

func (e failOnThresholdError) Error() string { return "" }

// rootCmd is the Cobra root command; it is the only permitted package-level variable.
var rootCmd = &cobra.Command{
	Use:   "gqls",
	Short: "GraphQL security scanner",
	Long:  "gqls scans GraphQL endpoints for common security misconfigurations and vulnerabilities.",
}

func init() {
	rootCmd.AddCommand(newScanCmd())
}

// newScanCmd builds and returns the "scan" subcommand.
func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "scan",
		Short:         "Scan a GraphQL endpoint for security issues",
		RunE:          runScan,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().String("url", "", "GraphQL endpoint URL to scan (required unless --curl / --curl-file is used)")
	cmd.Flags().StringArray("header", nil, "HTTP header in 'Name: Value' format (repeatable); overrides same-name headers from --curl")
	cmd.Flags().StringArray("checks", nil, "Check IDs to run (default: all)")
	cmd.Flags().StringArray("skip-checks", nil, "Check IDs to skip")
	cmd.Flags().String("output", "terminal", "Output format: terminal, txt, json, sarif")
	cmd.Flags().String("output-file", "", "Write output to this file path instead of stdout")
	cmd.Flags().String("fail-on", "none", "Exit 1 when a finding at or above this severity is found (INFO, LOW, MEDIUM, HIGH, CRITICAL, none)")
	cmd.Flags().Bool("no-color", false, "Disable ANSI colour codes in terminal output")
	cmd.Flags().Duration("timeout", 30*time.Second, "Per-request HTTP timeout")
	cmd.Flags().Int("rate-limit", 10, "Maximum HTTP requests per second")
	cmd.Flags().String("config", "", "Path to gqls.yaml config file")
	cmd.Flags().String("curl", "", "Raw curl command string to ingest (URL, headers, and body are extracted from it)")
	cmd.Flags().String("curl-file", "", "Path to a file containing a raw curl command (Bash or CMD multiline format)")
	cmd.Flags().StringArray("identity", nil, "Authorization-testing identity in 'name=userA;priv=10;tenant=t1;header=Authorization: Bearer X' format (repeatable)")
	cmd.Flags().Bool("authz-allow-mutations", false, "Allow authorization checks to send state-changing requests (e.g. GQL-A05); off by default")
	cmd.Flags().StringArray("authz-seed", nil, "Seed a known object id for object-level authz tests in 'field=id' format, e.g. 'user.id=42' (repeatable)")

	return cmd
}

// runScan is the RunE handler for the scan subcommand.
func runScan(cmd *cobra.Command, _ []string) error {
	v := viper.New()
	cfg, err := config.Load(v, cmd)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Capture CLI-only headers before applyCurlInput merges curl-file headers into
	// cfg.Headers. These become the "base" headers used by probing checks that must
	// not be influenced by curl-file-specific auth credentials.
	cliOnlyHeaders := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		cliOnlyHeaders[k] = v
	}

	// Apply curl ingestion before the URL check so that --curl / --curl-file
	// can satisfy the URL requirement on their own.
	parsedCurlReq, err := applyCurlInput(cmd, cfg)
	if err != nil {
		return err
	}

	if cfg.TargetURL == "" {
		return fmt.Errorf("--url is required (or provide a curl command via --curl / --curl-file)")
	}

	// Resolve header env-var expansions before building the HTTP clients.
	// resolvedHeaders includes all headers (curl-file + CLI --header flags).
	resolvedHeaders := cfg.ResolveHeaders()

	// resolvedCLIHeaders holds only the --header flag values with env vars expanded.
	// These are the "base" headers: no curl-file-specific credentials are included.
	resolvedCLIHeaders := make(map[string]string, len(cliOnlyHeaders))
	for k, v := range cliOnlyHeaders {
		resolvedCLIHeaders[k] = os.Expand(v, os.Getenv)
	}

	// Full client: carries all headers (curl-file + CLI). Used for schema extraction
	// and injection-based checks that must reproduce the original request context.
	client := transport.NewClient(cfg.Timeout, cfg.RateLimit, resolvedHeaders)

	// Base client: carries only CLI --header flags. Probing checks (GQL-002 through
	// GQL-010, excluding injection checks) use this client so their synthetic probes
	// are not coloured by curl-file authentication or other curl-specific headers.
	baseClient := transport.NewClient(cfg.Timeout, cfg.RateLimit, resolvedCLIHeaders)

	// Unauthenticated client: carries no headers at all. Used by checks that must
	// test public accessibility (GQL-001, GQL-012) without any credentials.
	unauthClient := transport.NewClient(cfg.Timeout, cfg.RateLimit, nil)

	// Authorization identities: one dedicated client per operator-supplied
	// identity, plus an auto-appended anonymous identity (reusing unauthClient)
	// when at least one authenticated identity is configured. These power the
	// stateful authz checks (BOLA/BFLA/BOPLA/cross-tenant).
	identities := buildIdentities(cfg, unauthClient)

	// Initialize and display progress early so user knows scan has started.
	allChecks := checks.All()
	selectedChecks := filterChecks(allChecks, cfg.Checks, cfg.SkipChecks)
	progress := newCheckProgress(cmd.ErrOrStderr(), len(selectedChecks), shouldShowLiveProgress(cmd, cfg.OutputFormat, cfg.OutputFile))
	progress.displayInitializing()
	defer progress.close()

	// Extract the schema before running checks.
	extractor := schema.NewExtractor(client, cfg.Timeout)
	extractResult, extractErr := extractor.Extract(context.Background(), cfg.TargetURL)
	if extractErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: schema extraction failed: %v\n", extractErr)
	}

	// When curl input was provided and schema extraction failed with the full client,
	// retry with the base client (CLI headers only, no curl-file headers). Some servers
	// enable introspection for anonymous/unauthenticated requests but disable it for
	// authenticated sessions; GQL-001 detects this via a bare client probe, and the
	// base-client retry here ensures GQL-006 (and other schema-dependent checks) can
	// still analyse the schema in those cases.
	if parsedCurlReq != nil && (extractResult == nil || extractResult.Schema == nil) {
		baseExtractor := schema.NewExtractor(baseClient, cfg.Timeout)
		retryResult, _ := baseExtractor.Extract(context.Background(), cfg.TargetURL)
		if retryResult != nil && retryResult.Schema != nil {
			extractResult = retryResult
			extractErr = nil
		}
	}

	var extractedSchema *schema.Schema
	var requestsMade int
	if extractResult != nil {
		extractedSchema = extractResult.Schema
		if extractedSchema != nil {
			requestsMade += extractedSchema.Metadata.ProbeCount
		}
		for _, e := range extractResult.Errors {
			if e.Fatal {
				fmt.Fprintf(cmd.ErrOrStderr(), "error: schema extraction [%s]: %s\n", e.Stage, e.Message)
			}
		}
	}

	scanStart := time.Now()
	var allFindings []checks.Finding
	var allCheckResults []checks.CheckResult
	checksRun := 0

	checkCtx := &checks.CheckContext{
		Target:                cfg.TargetURL,
		Schema:                extractedSchema,
		HTTPClient:            client,
		BaseHTTPClient:        baseClient,
		UnauthenticatedClient: unauthClient,
		ParsedCurl:            parsedCurlReq,
		Identities:            identities,
		AllowMutations:        cfg.AllowAuthzMutations,
		AuthzSeeds:            cfg.AuthzSeeds,
	}

	for _, chk := range selectedChecks {
		progress.startCheck(chk.ID())
		if chk.RequiresSchema() && checkCtx.Schema == nil {
			// Record that this check was skipped due to unavailable schema.
			allCheckResults = append(allCheckResults, checks.CheckResult{
				CheckID:    chk.ID(),
				Skipped:    true,
				SkipReason: "requires schema (unavailable)",
			})
			progress.finishCheck(chk.ID())
			continue
		}

		start := time.Now()
		result, err := chk.Run(context.Background(), checkCtx)
		result.Duration = time.Since(start)
		result.CheckID = chk.ID()
		result.Ran = true
		if err != nil {
			result.Error = err
		}
		checksRun++
		requestsMade += result.ProbeCount
		allCheckResults = append(allCheckResults, result)
		allFindings = append(allFindings, result.Findings...)
		progress.finishCheck(chk.ID())
	}

	scanDuration := time.Since(scanStart)

	// Suppress false-positive fingerprints.
	allFindings = suppressFalsePositives(allFindings, cfg.FalsePositives)

	scanResult := &reporter.ScanResult{
		ChecksRun:    checksRun,
		Duration:     scanDuration,
		RequestsMade: requestsMade,
		StartTime:    scanStart,
		Findings:     allFindings,
		Schema:       extractedSchema,
		CheckResults: allCheckResults,
	}

	// Select output writer. When writing to a file, disable ANSI codes
	// since files are not TTYs.
	out := cmd.OutOrStdout()
	noColor := cfg.NoColor
	var outputFile *os.File

	if cfg.OutputFile != "" {
		f, ferr := os.Create(cfg.OutputFile)
		if ferr != nil {
			return fmt.Errorf("opening output file: %w", ferr)
		}
		defer f.Close()
		out = f
		outputFile = f
		noColor = true
	}

	// Validate and create the reporter.
	format := strings.ToLower(cfg.OutputFormat)
	rep, repErr := reporter.New(format, out, noColor, Version)
	if repErr != nil {
		return fmt.Errorf("invalid output format: %w", repErr)
	}

	if err := rep.RenderReport(cfg.TargetURL, scanResult); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	if outputFile != nil {
		fmt.Printf("\n Report written to: %s\n", cfg.OutputFile)
	}

	// Return a sentinel (no message) when a finding meets or exceeds --fail-on
	// severity. Returning rather than calling os.Exit allows deferred cleanup
	// (including progress.close()) to execute before the process exits.
	if strings.ToUpper(cfg.FailOn) != "NONE" {
		failThreshold := checks.ParseSeverity(strings.ToUpper(cfg.FailOn))
		for _, f := range allFindings {
			if f.Severity >= failThreshold {
				return failOnThresholdError{}
			}
		}
	}

	return nil
}

func shouldShowLiveProgress(cmd *cobra.Command, outputFormat, outputFile string) bool {
	// Suppress live progress only for machine-readable formats. Progress is
	// rendered to stderr, so it remains safe to show while writing terminal/txt
	// reports to stdout or --output-file.
	format := strings.ToLower(strings.TrimSpace(outputFormat))
	if format == "json" || format == "sarif" {
		return false
	}
	_ = outputFile // kept for backwards-compatible signature used by tests/callers.
	errOut, ok := cmd.ErrOrStderr().(*os.File)
	if !ok {
		return false
	}
	fd := errOut.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// applyCurlInput reads --curl or --curl-file, parses the curl command, merges
// the result into cfg, and returns the structured CurlRequest so callers can
// propagate the full HTTP context to checks that require it.
//
// Merge rules:
//   - URL: cfg.TargetURL (set by --url) wins; falls back to the curl-parsed URL.
//   - Headers: curl headers form the base; --header flag values override them.
//   - Body: stored in cfg.CurlBody for backward compatibility.
//
// Returns nil (with no error) when neither --curl nor --curl-file was provided.
// --curl takes precedence over --curl-file when both are supplied.
func applyCurlInput(cmd *cobra.Command, cfg *config.ScanConfig) (*checks.CurlRequest, error) {
	raw, err := curlCommandString(cmd)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil // neither flag was provided
	}

	parsed, err := curlparser.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing curl input: %w", err)
	}

	// URL: explicit --url wins; otherwise use the one from the curl command.
	if cfg.TargetURL == "" {
		cfg.TargetURL = parsed.URL
	}

	// Headers: curl headers as the base layer, --header flags on top.
	merged := make(map[string]string, len(parsed.Headers)+len(cfg.Headers))
	for k, v := range parsed.Headers {
		merged[k] = v
	}
	for k, v := range cfg.Headers { // --header overrides curl headers
		merged[k] = v
	}
	cfg.Headers = merged

	// Body: seed for active injection checks.
	cfg.CurlBody = parsed.Body

	// parsed is *domain.CurlRequest (= *checks.CurlRequest via type alias).
	// Return directly — no field-by-field copy required.
	return parsed, nil
}

// curlCommandString returns the raw curl command string from --curl (inline)
// or --curl-file (file path). --curl takes precedence. Returns "" when
// neither flag was set.
func curlCommandString(cmd *cobra.Command) (string, error) {
	if inline, _ := cmd.Flags().GetString("curl"); inline != "" {
		return inline, nil
	}
	if path, _ := cmd.Flags().GetString("curl-file"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading --curl-file %q: %w", path, err)
		}
		return string(data), nil
	}
	return "", nil
}

// buildIdentities constructs one dedicated transport client per operator-supplied
// identity (expanding ${ENV_VAR} in header values), then appends the anonymous
// identity (reusing anonClient) when at least one authenticated identity exists.
// It returns nil when no identities were configured, so authz checks skip cleanly.
func buildIdentities(cfg *config.ScanConfig, anonClient *transport.Client) []authz.Identity {
	if len(cfg.Identities) == 0 {
		return nil
	}
	idents := make([]authz.Identity, 0, len(cfg.Identities)+1)
	for _, ic := range cfg.Identities {
		hdrs := config.ResolveIdentityHeaders(ic)
		idents = append(idents, authz.Identity{
			Name:      ic.Name,
			Privilege: ic.Privilege,
			Tenant:    ic.Tenant,
			Client:    transport.NewClient(cfg.Timeout, cfg.RateLimit, hdrs),
			Headers:   hdrs,
		})
	}
	return authz.WithAnonymous(idents, anonClient)
}

// filterChecks returns the subset of checks to run based on allow and deny lists.
func filterChecks(all []checks.Check, allow, deny []string) []checks.Check {
	denySet := make(map[string]bool, len(deny))
	for _, id := range deny {
		denySet[id] = true
	}

	allowSet := make(map[string]bool, len(allow))
	for _, id := range allow {
		allowSet[id] = true
	}

	var out []checks.Check
	for _, c := range all {
		if denySet[c.ID()] {
			continue
		}
		if len(allowSet) > 0 && !allowSet[c.ID()] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// suppressFalsePositives removes any finding whose Fingerprint is in the suppression list.
func suppressFalsePositives(findings []checks.Finding, fps []string) []checks.Finding {
	if len(fps) == 0 {
		return findings
	}
	fpSet := make(map[string]bool, len(fps))
	for _, fp := range fps {
		fpSet[fp] = true
	}
	out := findings[:0]
	for _, f := range findings {
		if !fpSet[f.Fingerprint] {
			out = append(out, f)
		}
	}
	return out
}
