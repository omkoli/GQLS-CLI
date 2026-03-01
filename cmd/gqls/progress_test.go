package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckProgressRendersCompletion(t *testing.T) {
	var buf bytes.Buffer
	p := newCheckProgress(&buf, 2, true)

	p.startCheck("GQL-001")
	p.finishCheck("GQL-001")
	p.startCheck("GQL-002")
	p.finishCheck("GQL-002")
	p.close()

	out := buf.String()
	if !strings.Contains(out, "Checks 100%") {
		t.Fatalf("expected completion percentage in output, got %q", out)
	}
	if !strings.Contains(out, "2/2") {
		t.Fatalf("expected done/total counter in output, got %q", out)
	}
	if !strings.Contains(out, "complete") {
		t.Fatalf("expected complete status in output, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected trailing newline, got %q", out)
	}
}

func TestCheckProgressDisabledProducesNoOutput(t *testing.T) {
	var buf bytes.Buffer
	p := newCheckProgress(&buf, 1, false)

	p.startCheck("GQL-001")
	p.finishCheck("GQL-001")
	p.close()

	if buf.Len() != 0 {
		t.Fatalf("expected no output when disabled, got %q", buf.String())
	}
}

func TestShouldShowLiveProgressGuards(t *testing.T) {
	cmd := newScanCmd()
	cmd.SetErr(&bytes.Buffer{})

	if shouldShowLiveProgress(cmd, "json", "") {
		t.Fatal("expected disabled for non-terminal output format")
	}
	if shouldShowLiveProgress(cmd, "terminal", "report.txt") {
		t.Fatal("expected disabled when output file is set")
	}
	if shouldShowLiveProgress(cmd, "terminal", "") {
		t.Fatal("expected disabled when stderr is not an *os.File")
	}
}
