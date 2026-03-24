package utils

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

func PrintBanner(silent bool) {
	if silent {
		return
	}
	banner := `
  ____        _     _             __  __
 / ___| _   _| |__ | |_ _   _ _ _ \ \/ /
 \___ \| | | | '_ \| __| | | | '_| >  <
  ___) | |_| | |_) | |_| |_| | |  / /\ \
 |____/ \__,_|_.__/ \__|\__, |_| /_/  \_\
                        |___/
`
	fmt.Fprintln(os.Stdout, banner)
	fmt.Fprintln(os.Stdout, "SubzyX - Subdomain Takeover Scanner")
}

// ProgressBar provides a lightweight in-terminal progress indicator.
type ProgressBar struct {
	total   int
	current int
	silent  bool
	json    bool
	mu      sync.Mutex
}

func NewProgressBar(total int, silent bool, json bool) *ProgressBar {
	return &ProgressBar{total: total, silent: silent, json: json}
}

func (p *ProgressBar) Increment() {
	if p.silent || p.json || p.total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	percent := (p.current * 100) / p.total
	filled := percent / 5
	bar := strings.Repeat("#", filled) + strings.Repeat("-", 20-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %d%% (%d/%d)", bar, percent, p.current, p.total)
}

func (p *ProgressBar) Done() {
	if p.silent || p.json || p.total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintln(os.Stderr)
}
