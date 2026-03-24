package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"subzyx/internal/output"
	"subzyx/internal/scanner"
)

var (
	domain           string
	threads          int
	outputFile       string
	timeoutSeconds   int
	silent           bool
	jsonOutput       bool
	verbose          bool
	fingerprintsFile string
	rateLimit        int
)

var rootCmd = &cobra.Command{
	Use:   "subzyx",
	Short: "Subdomain takeover detector",
	Long:  "SubzyX enumerates subdomains and detects potential or confirmed subdomain takeover vulnerabilities.",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanner.Options{
			Domain:           domain,
			Threads:          threads,
			OutputFile:       outputFile,
			Timeout:          time.Duration(timeoutSeconds) * time.Second,
			Silent:           silent,
			JSONOutput:       jsonOutput,
			Verbose:          verbose,
			FingerprintsPath: fingerprintsFile,
			RateLimit:        rateLimit,
		}

		engine, err := scanner.New(opts)
		if err != nil {
			return err
		}

		report, err := engine.Run(context.Background())
		if err != nil {
			return err
		}

		renderOpts := output.RenderOptions{
			Silent:     silent,
			JSONOutput: jsonOutput,
			OutputFile: outputFile,
		}
		if err := output.Render(report, renderOpts); err != nil {
			return err
		}

		return nil
	},
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func init() {
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target root domain (required)")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Number of concurrent workers")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	rootCmd.Flags().IntVar(&timeoutSeconds, "timeout", 10, "HTTP timeout in seconds")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "Silent mode (only print findings)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Print structured JSON output")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose logs")
	rootCmd.Flags().StringVar(&fingerprintsFile, "fingerprints", "fingerprints.json", "Path to fingerprints JSON file")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 20, "HTTP requests per second")

	_ = rootCmd.MarkFlagRequired("domain")
}
