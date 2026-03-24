package enum

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"subzyx/internal/utils"
)

// EnumerateSubdomains executes subfinder and returns unique discovered subdomains.
func EnumerateSubdomains(ctx context.Context, domain string, logger *utils.Logger) ([]string, error) {
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, errors.New("subfinder binary not found in PATH; install it or add it to PATH")
	}

	cmd := exec.CommandContext(ctx, "subfinder", "-silent", "-all", "-d", domain)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to capture subfinder output: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start subfinder: %w", err)
	}

	found := make(map[string]struct{})
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		host := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if host == "" {
			continue
		}
		found[host] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading subfinder output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("subfinder failed: %w", err)
	}

	// Always include root domain for direct target probing.
	found[strings.ToLower(domain)] = struct{}{}

	results := make([]string, 0, len(found))
	for host := range found {
		results = append(results, host)
	}
	sort.Strings(results)
	logger.Verbosef("Enumerated %d unique subdomains", len(results))

	return results, nil
}
