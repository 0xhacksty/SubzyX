package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"subzyx/internal/scanner"
)

// RenderOptions controls console and file output behavior.
type RenderOptions struct {
	Silent     bool
	JSONOutput bool
	OutputFile string
}

func Render(report *scanner.Report, opts RenderOptions) error {
	if opts.JSONOutput {
		payload, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if !opts.Silent {
			fmt.Println(string(payload))
		}
		if opts.OutputFile != "" {
			if err := os.WriteFile(opts.OutputFile, payload, 0o644); err != nil {
				return err
			}
		}
		return nil
	}

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	lines := make([]string, 0, len(report.Results)+2)
	for _, r := range report.Results {
		line := formatLine(r)
		switch r.Status {
		case scanner.StatusConfirmed:
			if !opts.Silent {
				fmt.Println(red(line))
			} else {
				fmt.Println(line)
			}
			lines = append(lines, "[CONFIRMED] "+line)
		case scanner.StatusPotential:
			if !opts.Silent {
				fmt.Println(yellow(line))
			} else {
				fmt.Println(line)
			}
			lines = append(lines, "[POTENTIAL] "+line)
		default:
			if !opts.Silent {
				fmt.Println(green(line))
				lines = append(lines, "[SAFE] "+line)
			}
		}
	}

	summary := fmt.Sprintf("Summary: total=%d confirmed=%d potential=%d safe=%d wildcard_dns=%t",
		report.Total, report.Confirmed, report.Potential, report.Safe, report.WildcardDNS)
	if !opts.Silent {
		fmt.Println(summary)
	}
	lines = append(lines, summary)

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	return nil
}

func formatLine(r scanner.Result) string {
	service := "Unknown"
	if r.Service != "" {
		service = r.Service
	}
	return fmt.Sprintf("[%s] %s -> %s (%s)", r.Status, r.Subdomain, service, r.Reason)
}
