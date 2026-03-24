package utils

import (
	"fmt"
	"os"
)

// Logger supports silent and verbose output modes.
type Logger struct {
	silent  bool
	verbose bool
}

func NewLogger(silent bool, verbose bool) *Logger {
	return &Logger{silent: silent, verbose: verbose}
}

func (l *Logger) Infof(format string, args ...any) {
	if l.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func (l *Logger) Verbosef(format string, args ...any) {
	if l.silent || !l.verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	if l.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	if l.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}
