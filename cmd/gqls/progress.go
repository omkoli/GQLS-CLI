package main

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// checkProgress renders a single-line live progress bar for sequential check runs.
type checkProgress struct {
	out     io.Writer
	total   int
	done    int
	current string
	start   time.Time
	enabled bool
}

func newCheckProgress(out io.Writer, total int, enabled bool) *checkProgress {
	return &checkProgress{out: out, total: total, start: time.Now(), enabled: enabled}
}

func (p *checkProgress) displayInitializing() {
	if !p.enabled {
		return
	}
	p.current = "Initializing scan..."
	_, _ = fmt.Fprintf(p.out, "%s\033[K", p.render())
	p.flush()
}

func (p *checkProgress) startCheck(checkID string) {
	if !p.enabled {
		return
	}
	p.current = checkID
	_, _ = fmt.Fprintf(p.out, "\r%s\033[K", p.render())
	p.flush()
}

func (p *checkProgress) finishCheck(checkID string) {
	p.done++
	if !p.enabled {
		return
	}
	_, _ = fmt.Fprintf(p.out, "\r%s\033[K", p.render())
	p.flush()
}

func (p *checkProgress) close() {
	if !p.enabled {
		return
	}
	percent := 0
	if p.total > 0 {
		percent = p.done * 100 / p.total
	}
	_, _ = fmt.Fprintf(p.out, "\rChecks %d%% (%d/%d checks) - complete\n", percent, p.done, p.total)
	p.flush()
}

func (p *checkProgress) flush() {
	if f, ok := p.out.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
}

func (p *checkProgress) render() string {
	const width = 10
	if p.total <= 0 {
		return "Running checks..."
	}

	filled := p.done * width / p.total
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}

	percent := p.done * 100 / p.total
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)

	current := p.current
	if current == "" {
		current = "initializing"
	}

	return fmt.Sprintf("[%s] %d%%  (%d/%d checks)  Current: %s", bar, percent, p.done, p.total, current)
}
