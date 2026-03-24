package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"subzyx/internal/enum"
	"subzyx/internal/fingerprints"
	"subzyx/internal/resolver"
	"subzyx/internal/utils"
)

type candidate struct {
	dns resolver.DNSResult
}

// Engine orchestrates enumeration, DNS checks, probing and matching.
type Engine struct {
	opts       Options
	logger     *utils.Logger
	fpStore    *fingerprints.Store
	resolver   *resolver.Resolver
	httpClient *retryablehttp.Client
}

func New(opts Options) (*Engine, error) {
	domain := strings.TrimSpace(strings.ToLower(opts.Domain))
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	opts.Domain = strings.TrimSuffix(domain, ".")

	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if strings.TrimSpace(opts.FingerprintsPath) == "" {
		opts.FingerprintsPath = "fingerprints.json"
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = 20
	}

	store, err := fingerprints.Load(opts.FingerprintsPath)
	if err != nil {
		return nil, err
	}

	httpOpts := retryablehttp.DefaultOptionsSingle
	httpOpts.RetryMax = 2
	httpOpts.RetryWaitMin = 250 * time.Millisecond
	httpOpts.RetryWaitMax = 1200 * time.Millisecond
	httpOpts.Timeout = opts.Timeout
	client := retryablehttp.NewClient(httpOpts)

	logger := utils.NewLogger(opts.Silent, opts.Verbose)

	return &Engine{
		opts:       opts,
		logger:     logger,
		fpStore:    store,
		resolver:   resolver.New("1.1.1.1:53", opts.Timeout),
		httpClient: client,
	}, nil
}

func (e *Engine) Run(ctx context.Context) (*Report, error) {
	utils.PrintBanner(e.opts.Silent)
	e.logger.Infof("Starting scan for %s", e.opts.Domain)

	subdomains, enumErr := enum.EnumerateSubdomains(ctx, e.opts.Domain, e.logger)
	if enumErr != nil {
		e.logger.Warnf("Subdomain enumeration failed (%v), continuing with root domain only", enumErr)
		subdomains = []string{e.opts.Domain}
	}
	subdomains = dedupe(subdomains)

	wildcardActive, wildcardIPs := e.detectWildcard(ctx)
	e.logger.Verbosef("Wildcard DNS active: %t, wildcard IPs: %v", wildcardActive, wildcardIPs)

	progress := utils.NewProgressBar(len(subdomains)*2, e.opts.Silent, e.opts.JSONOutput)
	dnsResults := e.resolveAll(ctx, subdomains, progress)

	baseResults := make(map[string]Result, len(dnsResults))
	candidates := make([]candidate, 0)
	for _, d := range dnsResults {
		res := Result{
			Subdomain: d.Subdomain,
			Status:    StatusSafe,
			Reason:    "No takeover indicators",
			CNAME:     d.CNAME,
			IPs:       d.IPs,
			Error:     d.Error,
		}

		if wildcardActive && d.CNAME == "" && sameIPSet(d.IPs, wildcardIPs) {
			res.Reason = "Wildcard DNS record detected; skipped to reduce false positives"
			baseResults[d.Subdomain] = res
			progress.Increment()
			continue
		}

		externalCNAME := d.CNAME != "" && !sameOrSubdomain(d.CNAME, e.opts.Domain)
		if externalCNAME || !d.HasValidIP {
			candidates = append(candidates, candidate{dns: d})
		}
		baseResults[d.Subdomain] = res
	}

	probed := e.probeCandidates(ctx, candidates, progress)
	progress.Done()

	for _, p := range probed {
		baseResults[p.Subdomain] = EvaluateCandidate(p, e.fpStore, e.opts.Domain)
	}

	results := make([]Result, 0, len(baseResults))
	for _, r := range baseResults {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Subdomain < results[j].Subdomain })

	report := &Report{
		Domain:      e.opts.Domain,
		GeneratedAt: time.Now().UTC(),
		WildcardDNS: wildcardActive,
		Total:       len(results),
		Results:     results,
	}
	for _, r := range results {
		switch r.Status {
		case StatusConfirmed:
			report.Confirmed++
		case StatusPotential:
			report.Potential++
		default:
			report.Safe++
		}
	}

	return report, nil
}

func (e *Engine) resolveAll(ctx context.Context, subs []string, progress *utils.ProgressBar) []resolver.DNSResult {
	jobs := make(chan string)
	results := make(chan resolver.DNSResult)

	var wg sync.WaitGroup
	for i := 0; i < e.opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				res := e.resolver.Resolve(ctx, sub)
				results <- res
				progress.Increment()
			}
		}()
	}

	go func() {
		for _, sub := range subs {
			jobs <- sub
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]resolver.DNSResult, 0, len(subs))
	for r := range results {
		out = append(out, r)
	}
	return out
}

func (e *Engine) probeCandidates(ctx context.Context, cands []candidate, progress *utils.ProgressBar) []probedCandidate {
	jobs := make(chan candidate)
	results := make(chan probedCandidate)

	var wg sync.WaitGroup
	interval := time.Second / time.Duration(e.opts.RateLimit)
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)

	for i := 0; i < e.opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}

				resp, err := e.probeHost(ctx, c.dns.Subdomain)
				results <- probedCandidate{DNSResult: c.dns, Response: resp, ProbeError: err}
				progress.Increment()
			}
		}()
	}

	go func() {
		for _, c := range cands {
			jobs <- c
		}
		close(jobs)
		wg.Wait()
		ticker.Stop()
		close(results)
	}()

	out := make([]probedCandidate, 0, len(cands))
	for r := range results {
		out = append(out, r)
	}
	return out
}

type probedCandidate struct {
	resolver.DNSResult
	Response   *HTTPResponse
	ProbeError error
}

func (e *Engine) probeHost(ctx context.Context, host string) (*HTTPResponse, error) {
	urls := []string{"https://" + host, "http://" + host}
	var lastErr error
	for _, u := range urls {
		req, err := retryablehttp.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := e.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()

		headers := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = strings.Join(v, "; ")
			}
		}

		return &HTTPResponse{
			URL:        u,
			StatusCode: resp.StatusCode,
			Body:       string(body),
			Headers:    headers,
		}, nil
	}

	return nil, lastErr
}

// EvaluateCandidate combines DNS, CNAME fingerprints and HTTP body signatures.
func EvaluateCandidate(p probedCandidate, store *fingerprints.Store, domain string) Result {
	res := Result{
		Subdomain: p.Subdomain,
		Status:    StatusSafe,
		Reason:    "No takeover indicators",
		CNAME:     p.CNAME,
		IPs:       p.IPs,
	}
	if p.ProbeError != nil {
		res.Error = p.ProbeError.Error()
	}
	if p.Response != nil {
		res.HTTPStatusCode = p.Response.StatusCode
	}

	cnameMatches := store.MatchByCNAME(p.CNAME)
	bodyMatch := false
	bodyService := ""
	bodyToken := ""

	if p.Response != nil {
		if ok, svc, token := store.MatchBody(p.Response.Body, cnameMatches); ok {
			bodyMatch = true
			bodyService = svc
			bodyToken = token
		} else if ok, svc, token := store.MatchBodyAny(p.Response.Body); ok {
			bodyMatch = true
			bodyService = svc
			bodyToken = token
		}
	}

	if len(cnameMatches) > 0 && bodyMatch {
		res.Status = StatusConfirmed
		res.Service = bodyService
		res.Reason = "CNAME and HTTP fingerprint matched"
		res.MatchedString = bodyToken
		return res
	}

	if len(cnameMatches) > 0 {
		res.Status = StatusPotential
		res.Service = cnameMatches[0].Service
		res.Reason = "CNAME matched known takeover-prone service"
		return res
	}

	if bodyMatch {
		res.Status = StatusPotential
		res.Service = bodyService
		res.Reason = "HTTP response matched known takeover fingerprint"
		res.MatchedString = bodyToken
		return res
	}

	if !p.HasValidIP || (p.CNAME != "" && !sameOrSubdomain(p.CNAME, domain)) {
		res.Status = StatusPotential
		res.Reason = "Dangling DNS detected without definitive service fingerprint"
	}

	return res
}

func (e *Engine) detectWildcard(ctx context.Context) (bool, []string) {
	host := fmt.Sprintf("%s.%s", randomLabel(12), e.opts.Domain)
	res := e.resolver.Resolve(ctx, host)
	return res.HasValidIP, res.IPs
}

func randomLabel(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	s := make([]rune, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range s {
		s[i] = letters[r.Intn(len(letters))]
	}
	return string(s)
}

func sameOrSubdomain(host string, root string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	r := strings.TrimSuffix(strings.ToLower(root), ".")
	return h == r || strings.HasSuffix(h, "."+r)
}

func sameIPSet(left []string, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	m := make(map[string]struct{}, len(right))
	for _, ip := range right {
		m[ip] = struct{}{}
	}
	for _, ip := range left {
		if _, ok := m[ip]; !ok {
			return false
		}
	}
	return true
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		n := strings.TrimSpace(strings.ToLower(item))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
