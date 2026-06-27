package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/domain"
	"github.com/gqls-cli/gqls/pkg/schema"
)

// TXTRenderer writes a clean, fully self-contained plain-text report.
// It contains no ANSI codes, no JSON, and no markdown — readable in any
// text editor, email body, or ticket system.
type TXTRenderer struct {
	writer  io.Writer
	width   int    // line wrap width, default 80
	Version string // tool version string, default "dev"
}

// NewTXTRenderer creates a TXTRenderer with the default line width of 80.
func NewTXTRenderer(w io.Writer) *TXTRenderer {
	return &TXTRenderer{writer: w, width: 80, Version: "dev"}
}

// NewTXTRendererWithWidth creates a TXTRenderer with a custom line width.
func NewTXTRendererWithWidth(w io.Writer, width int) *TXTRenderer {
	return &TXTRenderer{writer: w, width: width, Version: "dev"}
}

// RenderReport writes the complete plain-text report to the writer in one atomic call.
// Sections in order: header, findings index, individual findings, clean checks, skipped checks, footer.
func (r *TXTRenderer) RenderReport(target string, result *ScanResult) error {
	var sb strings.Builder
	r.writeHeader(&sb, target, result)
	sorted := sortedFindings(result.Findings)
	if len(sorted) > 0 {
		r.writeTOC(&sb, sorted)
		for i, f := range sorted {
			r.writeFindingBlock(&sb, f, i+1)
		}
	}
	r.writeCleanChecks(&sb, result.CheckResults)
	r.writeSkippedChecks(&sb, result.CheckResults)
	r.writeFooter(&sb, target, result.StartTime)
	_, err := fmt.Fprint(r.writer, sb.String())
	return err
}

// RenderFinding writes a single finding block without a header/footer/TOC.
// The finding number prefix is omitted since no index is available.
func (r *TXTRenderer) RenderFinding(f domain.Finding) error {
	var sb strings.Builder
	r.writeFindingBlockNoIndex(&sb, f)
	_, err := fmt.Fprint(r.writer, sb.String())
	return err
}

// RenderSummary writes just the header summary, clean checks, and skipped checks without individual findings.
func (r *TXTRenderer) RenderSummary(result *ScanResult) error {
	var sb strings.Builder
	r.writeHeader(&sb, "", result)
	r.writeCleanChecks(&sb, result.CheckResults)
	r.writeSkippedChecks(&sb, result.CheckResults)
	r.writeFooter(&sb, "", result.StartTime)
	_, err := fmt.Fprint(r.writer, sb.String())
	return err
}

// ── internal helpers ────────────────────────────────────────────────────────

func (r *TXTRenderer) sep(ch string) string {
	return strings.Repeat(ch, r.width)
}

// writeHeader renders the report header section.
func (r *TXTRenderer) writeHeader(sb *strings.Builder, target string, result *ScanResult) {
	eq := r.sep("=")
	sb.WriteString(eq)
	sb.WriteString("\n")
	sb.WriteString("GQLS SECURITY SCAN REPORT\n")
	sb.WriteString(eq)
	sb.WriteString("\n")

	// Label column is 13 chars wide.
	label := func(name, value string) string {
		return fmt.Sprintf("%-13s%s\n", name, value)
	}

	if target != "" {
		sb.WriteString(label("Target:", target))
	}

	scanDate := result.StartTime
	if scanDate.IsZero() {
		scanDate = time.Now()
	}
	sb.WriteString(label("Scan Date:", scanDate.UTC().Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(label("Duration:", formatDuration(result.Duration)))
	sb.WriteString(label("Checks Run:", fmt.Sprintf("%d", result.ChecksRun)))
	sb.WriteString(label("Requests:", fmt.Sprintf("%d", result.RequestsMade)))

	schemaLine := schemaDescription(result.Schema)
	sb.WriteString(label("Schema:", schemaLine))

	sb.WriteString("\n")
	sb.WriteString("Findings Summary:\n")

	counts := map[domain.Severity]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	total := len(result.Findings)

	levels := []domain.Severity{domain.CRITICAL, domain.HIGH, domain.MEDIUM, domain.LOW, domain.INFO}
	for _, sev := range levels {
		n := counts[sev]
		sb.WriteString(fmt.Sprintf("  %-8s  %d\n", sev.String(), n))
	}
	sb.WriteString("  --------  --\n")
	sb.WriteString(fmt.Sprintf("  %-8s  %d\n", "TOTAL", total))
	sb.WriteString(eq)
	sb.WriteString("\n")
}

// writeTOC renders the findings index table.
func (r *TXTRenderer) writeTOC(sb *strings.Builder, findings []domain.Finding) {
	dash := r.sep("-")
	sb.WriteString("FINDINGS INDEX\n")
	sb.WriteString(dash)
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf(" %-3s %-9s %-10s %s\n", "#", "Sev", "Check ID", "Title"))
	sb.WriteString(dash)
	sb.WriteString("\n")

	// Title column width: width - 4(#) - 10(Sev) - 11(CheckID) - spaces
	// " #   Sev       Check ID   Title"
	// col widths: 1+3=4, 1+9=10, 1+10=11, rest
	titleWidth := r.width - 4 - 10 - 11
	if titleWidth < 10 {
		titleWidth = 10
	}

	for i, f := range findings {
		title := f.Title
		if title == "" {
			title = f.CheckName
		}
		if len(title) > titleWidth {
			title = title[:titleWidth-3] + "..."
		}
		sb.WriteString(fmt.Sprintf(" %-3d %-9s %-10s %s\n", i+1, f.Severity.String(), f.CheckID, title))
	}
	sb.WriteString(dash)
	sb.WriteString("\n")
}

// writeFindingBlock renders a single finding with its index number.
func (r *TXTRenderer) writeFindingBlock(sb *strings.Builder, f domain.Finding, idx int) {
	eq := r.sep("=")
	sb.WriteString(eq)
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("FINDING #%d — %s\n", idx, f.Severity.String()))
	title := f.Title
	if title == "" {
		title = f.CheckName
	}
	sb.WriteString(fmt.Sprintf("%s: %s\n", f.CheckID, title))
	sb.WriteString(eq)
	sb.WriteString("\n\n")
	r.writeFindingContent(sb, f)
}

// writeFindingBlockNoIndex renders a single finding without an index prefix.
func (r *TXTRenderer) writeFindingBlockNoIndex(sb *strings.Builder, f domain.Finding) {
	title := f.Title
	if title == "" {
		title = f.CheckName
	}
	sb.WriteString(fmt.Sprintf("%s: %s\n", f.CheckID, title))
	sb.WriteString(r.sep("-"))
	sb.WriteString("\n\n")
	r.writeFindingContent(sb, f)
}

// writeFindingContent writes the body sections of a finding block.
func (r *TXTRenderer) writeFindingContent(sb *strings.Builder, f domain.Finding) {
	wrapWidth := r.width - 2

	writeSection := func(label, content string) {
		sb.WriteString(label)
		sb.WriteString("\n")
		indented := indentLines(wordWrap(content, wrapWidth), "  ")
		sb.WriteString(indented)
		sb.WriteString("\n\n")
	}

	writeSection("WHAT WAS FOUND", f.Description)

	if cls := classificationLine(f); cls != "" {
		writeSection("CLASSIFICATION", cls)
	}

	if f.ReproRequest != nil {
		sb.WriteString("REPRODUCE\n")
		curl := r.formatCurlTXT(f.ReproRequest, f.ReproBody)
		sb.WriteString(curl)
		sb.WriteString("\n\n")
	}

	writeSection("ATTACKER IMPACT", f.Impact)

	// Remediation: preserve structure, only reflow prose lines.
	sb.WriteString("REMEDIATION\n")
	remWrap := wrapRemediation(f.Remediation, wrapWidth)
	indented := indentLines(remWrap, "  ")
	sb.WriteString(indented)
	sb.WriteString("\n\n")

	if len(f.References) > 0 {
		sb.WriteString("REFERENCES\n")
		for _, ref := range f.References {
			sb.WriteString("  ")
			sb.WriteString(ref)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(r.sep("-"))
	sb.WriteString("\n")
}

// writeCleanChecks renders a section explaining why each check that ran found no issues.
// This helps readers understand whether the absence of findings reflects real protection
// or a limitation of the scan (e.g. schema unavailable, probes blocked).
func (r *TXTRenderer) writeCleanChecks(sb *strings.Builder, results []domain.CheckResult) {
	var clean []domain.CheckResult
	for _, cr := range results {
		if cr.Ran && !cr.Skipped && cr.Error == nil && len(cr.Findings) == 0 && cr.PassReason != "" {
			clean = append(clean, cr)
		}
	}
	if len(clean) == 0 {
		return
	}

	eq := r.sep("=")
	dash := r.sep("-")
	wrapWidth := r.width - 2

	sb.WriteString(eq)
	sb.WriteString("\n")
	sb.WriteString("CHECKS WITH NO FINDINGS\n")
	sb.WriteString(eq)
	sb.WriteString("\n\n")
	sb.WriteString("The following checks ran successfully and found no issues.\n")
	sb.WriteString("The explanation below describes why no finding was produced.\n\n")

	for _, cr := range clean {
		sb.WriteString(fmt.Sprintf("%-9s WHY NO FINDING\n", cr.CheckID))
		sb.WriteString(dash)
		sb.WriteString("\n")
		wrapped := indentLines(wordWrap(cr.PassReason, wrapWidth), "  ")
		sb.WriteString(wrapped)
		sb.WriteString("\n\n")

		if len(cr.PassProbes) > 0 {
			sb.WriteString(fmt.Sprintf("  PROBES SENT (%d)\n", len(cr.PassProbes)))
			for i, pp := range cr.PassProbes {
				sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, pp.Label))
				curl := r.formatCurlTXT(pp.Request, pp.Body)
				sb.WriteString(curl)
				sb.WriteString("\n\n")
			}
		} else {
			sb.WriteString("  (Schema analysis — no HTTP probes sent)\n\n")
		}
	}

	sb.WriteString(eq)
	sb.WriteString("\n")
}

// writeSkippedChecks renders the skipped checks section if any checks were skipped.
func (r *TXTRenderer) writeSkippedChecks(sb *strings.Builder, results []domain.CheckResult) {
	var skipped []domain.CheckResult
	for _, cr := range results {
		if cr.Skipped {
			skipped = append(skipped, cr)
		}
	}
	if len(skipped) == 0 {
		return
	}

	eq := r.sep("=")
	sb.WriteString(eq)
	sb.WriteString("\n")
	sb.WriteString("SKIPPED CHECKS\n")
	sb.WriteString(eq)
	sb.WriteString("\n\n")
	sb.WriteString("The following checks were skipped during this scan:\n\n")

	for _, cr := range skipped {
		sb.WriteString(fmt.Sprintf("  %-9s %s\n", cr.CheckID, cr.SkipReason))
	}

	sb.WriteString("\n")
	sb.WriteString(eq)
	sb.WriteString("\n")
}

// writeFooter renders the report footer with version and report ID.
func (r *TXTRenderer) writeFooter(sb *strings.Builder, target string, startTime time.Time) {
	eq := r.sep("=")
	sb.WriteString(eq)
	sb.WriteString("\n")
	sb.WriteString("END OF REPORT\n")
	version := r.Version
	if version == "" {
		version = "dev"
	}
	sb.WriteString(fmt.Sprintf("Generated by gqls v%s — https://github.com/gqls-cli/gqls\n", version))
	sb.WriteString(fmt.Sprintf("Report ID: %s\n", reportID(target, startTime)))
	sb.WriteString(eq)
	sb.WriteString("\n")
}

// formatCurlTXT generates a plain-text curl command from the request.
// If the full command fits within r.width chars (with 2-space indent), it is
// output on one line; otherwise each flag gets its own line with \ continuation.
// The Authorization header value is replaced with [REDACTED].
func (r *TXTRenderer) formatCurlTXT(req *http.Request, body []byte) string {
	if req == nil {
		return "  (no request captured)"
	}

	method := req.Method
	rawURL := req.URL.String()

	// Collect and sort header keys for deterministic output.
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	type headerPair struct{ k, v string }
	var headers []headerPair
	for _, k := range keys {
		// Skip Accept-Encoding header as it's added automatically by HTTP clients
		if strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range req.Header[k] {
			if strings.EqualFold(k, "Authorization") {
				v = "[REDACTED]"
			}
			headers = append(headers, headerPair{k, v})
		}
	}

	// Try single-line first.
	var parts []string
	parts = append(parts, fmt.Sprintf("curl -X %s %s", method, rawURL))
	for _, h := range headers {
		parts = append(parts, fmt.Sprintf("-H %q", h.k+": "+h.v))
	}
	if len(body) > 0 {
		parts = append(parts, fmt.Sprintf("-d %q", string(body)))
	}
	oneLine := "  " + strings.Join(parts, " ")
	if len(oneLine) <= r.width {
		return oneLine
	}

	// Multi-line with \ continuations.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  curl -X %s %s", method, rawURL))
	for _, h := range headers {
		sb.WriteString(" \\\n")
		sb.WriteString(fmt.Sprintf("    -H %q", h.k+": "+h.v))
	}
	if len(body) > 0 {
		sb.WriteString(" \\\n")
		sb.WriteString(fmt.Sprintf("    -d %q", string(body)))
	}
	return sb.String()
}

// ── utility functions ────────────────────────────────────────────────────────

// wordWrap wraps text at word boundaries so no line exceeds lineWidth characters.
// Rules:
//   - Double newlines (\n\n) are preserved as paragraph breaks.
//   - Single newlines within a paragraph are treated as spaces (standard reflow).
//   - Lines starting with 2+ spaces pass through unchanged (code/indented content).
//   - Empty lines pass through unchanged.
//   - Output lines have no trailing whitespace.
func wordWrap(text string, lineWidth int) string {
	if lineWidth <= 0 || text == "" {
		return text
	}

	// Split on paragraph breaks.
	paragraphs := strings.Split(text, "\n\n")
	result := make([]string, 0, len(paragraphs))

	for _, para := range paragraphs {
		if para == "" {
			result = append(result, "")
			continue
		}

		lines := strings.Split(para, "\n")
		var wrapped []string

		// Accumulate prose lines to reflow together.
		var prose []string
		flushProse := func() {
			if len(prose) > 0 {
				joined := strings.Join(prose, " ")
				wrapped = append(wrapped, wrapLine(joined, lineWidth)...)
				prose = nil
			}
		}

		for _, line := range lines {
			// Lines starting with 2+ spaces pass through as-is.
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				flushProse()
				wrapped = append(wrapped, line)
				continue
			}
			if line == "" {
				flushProse()
				wrapped = append(wrapped, "")
				continue
			}
			prose = append(prose, strings.TrimRight(line, " "))
		}
		flushProse()

		result = append(result, strings.Join(wrapped, "\n"))
	}

	return strings.Join(result, "\n\n")
}

// wrapLine wraps a single prose line at word boundaries without exceeding width.
func wrapLine(text string, width int) []string {
	if len(text) <= width {
		return []string{strings.TrimRight(text, " ")}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) <= width {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// wrapRemediation processes remediation text preserving code structure.
// Code lines (indented, tab-prefixed, or starting with code keywords) pass through;
// long prose lines are word-wrapped.
func wrapRemediation(text string, lineWidth int) string {
	if text == "" {
		return text
	}
	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" || isCodeLine(line) {
			result = append(result, line)
			continue
		}
		if len(line) <= lineWidth {
			result = append(result, line)
			continue
		}
		// Wrap this prose line.
		result = append(result, wrapLine(line, lineWidth)...)
	}
	return strings.Join(result, "\n")
}

// isCodeLine reports whether line should pass through without reflowing.
func isCodeLine(line string) bool {
	if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
		return true
	}
	codeStarters := []string{"new ", "use", "const ", "{", "}"}
	for _, s := range codeStarters {
		if strings.HasPrefix(line, s) {
			return true
		}
	}
	return false
}

// indentLines prepends prefix to every non-empty line in text.
func indentLines(text, prefix string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// formatDuration formats a duration into a compact human-readable string.
// Examples: "< 1s", "1.2s", "1m 8s", "2m 30s"
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %ds", mins, secs)
}

// schemaDescription returns a human-readable description of the schema state.
func schemaDescription(s *schema.Schema) string {
	if s == nil {
		return "Not available"
	}
	typeCount := len(s.Types)
	switch s.ExtractionMethod {
	case schema.MethodFieldSuggestion:
		return fmt.Sprintf("Reconstructed via field suggestions (partial)")
	case schema.MethodIntrospection:
		return fmt.Sprintf("Extracted via introspection (%d types)", typeCount)
	default:
		return fmt.Sprintf("Extracted (%d types)", typeCount)
	}
}

// reportID returns the first 12 hex characters of SHA-256(target + startTime RFC3339).
// This gives support teams a stable, reproducible identifier for a scan.
func reportID(target string, startTime time.Time) string {
	h := sha256.New()
	h.Write([]byte(target))
	h.Write([]byte(startTime.UTC().Format(time.RFC3339)))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// sortedFindings returns findings sorted by severity descending, then CheckID ascending.
func sortedFindings(findings []domain.Finding) []domain.Finding {
	out := make([]domain.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity // higher severity first
		}
		return out[i].CheckID < out[j].CheckID
	})
	return out
}
