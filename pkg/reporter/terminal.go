// Package reporter contains output formatters for scan results.
package reporter

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/gqls-cli/gqls/pkg/domain"
)

// Renderer writes styled terminal output for scan findings and summaries.
type Renderer struct {
	// NoColor disables all ANSI escape codes when true (suitable for CI).
	NoColor bool
	// Out is the writer to send output to.
	Out io.Writer

	criticalStyle lipgloss.Style
	highStyle     lipgloss.Style
	mediumStyle   lipgloss.Style
	lowStyle      lipgloss.Style
	infoStyle     lipgloss.Style
	headerStyle   lipgloss.Style
	labelStyle    lipgloss.Style
	dimStyle      lipgloss.Style
}

// NewRenderer creates a Renderer pre-configured with severity colour styles.
// When noColor is false the underlying lipgloss renderer is forced to TrueColor so
// that ANSI codes appear even when writing to a non-TTY (e.g. a file or test buffer).
// When noColor is true the profile is set to Ascii, which suppresses all escape codes.
func NewRenderer(out io.Writer, noColor bool) *Renderer {
	profile := termenv.TrueColor
	if noColor {
		profile = termenv.Ascii
	}
	// lipgloss.NewRenderer alone doesn't honour a WithProfile option reliably;
	// we must explicitly wire up a termenv.Output with the desired profile.
	tOut := termenv.NewOutput(out, termenv.WithProfile(profile))
	lr := lipgloss.NewRenderer(out)
	lr.SetOutput(tOut)
	lr.SetColorProfile(profile)
	return &Renderer{
		NoColor:       noColor,
		Out:           out,
		criticalStyle: lr.NewStyle().Bold(true).Foreground(lipgloss.Color("196")),
		highStyle:     lr.NewStyle().Foreground(lipgloss.Color("196")),
		mediumStyle:   lr.NewStyle().Foreground(lipgloss.Color("220")),
		lowStyle:      lr.NewStyle().Foreground(lipgloss.Color("46")),
		infoStyle:     lr.NewStyle().Foreground(lipgloss.Color("33")),
		headerStyle:   lr.NewStyle().Bold(true).Foreground(lipgloss.Color("255")),
		labelStyle:    lr.NewStyle().Bold(true),
		dimStyle:      lr.NewStyle().Foreground(lipgloss.Color("240")),
	}
}

// severityStyle returns the lipgloss style for the given severity.
func (r *Renderer) severityStyle(s domain.Severity) lipgloss.Style {
	switch s {
	case domain.CRITICAL:
		return r.criticalStyle
	case domain.HIGH:
		return r.highStyle
	case domain.MEDIUM:
		return r.mediumStyle
	case domain.LOW:
		return r.lowStyle
	default:
		return r.infoStyle
	}
}

// styled applies a lipgloss style unless NoColor is set.
func (r *Renderer) styled(style lipgloss.Style, text string) string {
	if r.NoColor {
		return text
	}
	return style.Render(text)
}

// RenderReport writes all findings then the summary to r.Out.
// It satisfies the Reporter interface.
func (r *Renderer) RenderReport(_ string, result *ScanResult) error {
	for _, f := range result.Findings {
		if err := r.RenderFinding(f); err != nil {
			return err
		}
	}
	return r.RenderSummary(result)
}

// RenderFinding writes a full finding block to r.Out.
// The block includes a severity-coloured header bar, WHAT WAS FOUND, REPRODUCE IT,
// ATTACKER IMPACT, FIX, and REFERENCES sections.
func (r *Renderer) RenderFinding(f domain.Finding) error {
	sStyle := r.severityStyle(f.Severity)
	bar := r.styled(sStyle, fmt.Sprintf("[ %s ] %s — %s", f.Severity.String(), f.CheckID, f.CheckName))

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(bar)
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 72))
	sb.WriteString("\n\n")

	writeSection := func(label, content string) {
		sb.WriteString(r.styled(r.labelStyle, label))
		sb.WriteString("\n")
		sb.WriteString("  ")
		sb.WriteString(content)
		sb.WriteString("\n\n")
	}

	writeSection("WHAT WAS FOUND", f.Description)

	if cls := classificationLine(f); cls != "" {
		writeSection("CLASSIFICATION", cls)
	}

	curlCmd := GenerateCurlCommand(f.ReproRequest, f.ReproBody)
	writeSection("REPRODUCE IT", curlCmd)

	writeSection("ATTACKER IMPACT", f.Impact)
	writeSection("FIX", f.Remediation)

	if len(f.References) > 0 {
		sb.WriteString(r.styled(r.labelStyle, "REFERENCES"))
		sb.WriteString("\n")
		for _, ref := range f.References {
			sb.WriteString("  • ")
			sb.WriteString(ref)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	_, err := fmt.Fprint(r.Out, sb.String())
	return err
}

// RenderSummary writes the scan summary table to r.Out.
// The table shows checks run, total duration, requests made, a severity bar chart,
// and a section explaining why each clean check produced no findings.
func (r *Renderer) RenderSummary(result *ScanResult) error {
	counts := map[domain.Severity]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(r.styled(r.headerStyle, "SCAN SUMMARY"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 72))
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("  Checks run     : %d\n", result.ChecksRun))
	sb.WriteString(fmt.Sprintf("  Duration       : %s\n", result.Duration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("  Requests made  : %d\n", result.RequestsMade))
	sb.WriteString("\n")

	total := len(result.Findings)
	sb.WriteString(r.styled(r.labelStyle, "  Findings by severity:\n"))

	levels := []domain.Severity{domain.CRITICAL, domain.HIGH, domain.MEDIUM, domain.LOW, domain.INFO}
	for _, sev := range levels {
		n := counts[sev]
		bar := buildBar(n, total, 30)
		label := fmt.Sprintf("  %-10s %s %d", sev.String(), r.styled(r.severityStyle(sev), bar), n)
		sb.WriteString(label)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Render clean checks section — explains why each passing check found nothing.
	var clean []domain.CheckResult
	for _, cr := range result.CheckResults {
		if cr.Ran && !cr.Skipped && cr.Error == nil && len(cr.Findings) == 0 && cr.PassReason != "" {
			clean = append(clean, cr)
		}
	}
	if len(clean) > 0 {
		sb.WriteString(r.styled(r.headerStyle, "CHECKS WITH NO FINDINGS"))
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("─", 72))
		sb.WriteString("\n")
		sb.WriteString("  The following checks ran successfully and found no issues.\n\n")
		for _, cr := range clean {
			sb.WriteString(r.styled(r.labelStyle, fmt.Sprintf("  %s", cr.CheckID)))
			sb.WriteString("\n")
			sb.WriteString(r.styled(r.dimStyle, "  "+cr.PassReason))
			sb.WriteString("\n\n")
			if len(cr.PassProbes) > 0 {
				sb.WriteString(r.styled(r.labelStyle, fmt.Sprintf("  Probes sent (%d):\n", len(cr.PassProbes))))
				for i, pp := range cr.PassProbes {
					sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, r.styled(r.dimStyle, pp.Label)))
					curl := GenerateCurlCommand(pp.Request, pp.Body)
					// Indent each curl line by 6 spaces for alignment under the probe index.
					for _, line := range strings.Split(curl, "\n") {
						sb.WriteString("      ")
						sb.WriteString(line)
						sb.WriteString("\n")
					}
					sb.WriteString("\n")
				}
			} else {
				sb.WriteString(r.styled(r.dimStyle, "  (Schema analysis — no HTTP probes sent)\n\n"))
			}
		}
	}

	_, err := fmt.Fprint(r.Out, sb.String())
	return err
}

// GenerateCurlCommand reconstructs a copy-pasteable curl command from req and body.
// The Authorization header value is replaced with "[REDACTED]".
func GenerateCurlCommand(req *http.Request, body []byte) string {
	if req == nil {
		return "(no request captured)"
	}

	var sb strings.Builder
	sb.WriteString("curl -X ")
	sb.WriteString(req.Method)
	sb.WriteString(" \\\n")
	sb.WriteString("  '")
	sb.WriteString(req.URL.String())
	sb.WriteString("'")

	// Collect and sort header keys for deterministic output.
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		vals := req.Header[k]
		// Skip Accept-Encoding header as it's added automatically by HTTP clients
		if strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range vals {
			if strings.EqualFold(k, "Authorization") {
				v = "[REDACTED]"
			}
			sb.WriteString(" \\\n  -H '")
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("'")
		}
	}

	if len(body) > 0 {
		sb.WriteString(" \\\n  --data-raw '")
		sb.WriteString(strings.ReplaceAll(string(body), "'", "'\\''"))
		sb.WriteString("'")
	}

	return sb.String()
}

// buildBar constructs a proportional bar using block characters.
// filled uses '█' and empty uses '░'.
func buildBar(count, total, width int) string {
	if width <= 0 {
		return ""
	}
	if total == 0 || count == 0 {
		return strings.Repeat("░", width)
	}
	filled := (count * width) / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
