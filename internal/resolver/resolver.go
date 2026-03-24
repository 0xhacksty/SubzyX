package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSResult contains DNS discovery data for a subdomain.
type DNSResult struct {
	Subdomain  string   `json:"subdomain"`
	CNAME      string   `json:"cname,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	HasValidIP bool     `json:"has_valid_ip"`
	Error      string   `json:"error,omitempty"`
}

// Resolver resolves A/AAAA/CNAME records using miekg/dns.
type Resolver struct {
	client     *dns.Client
	nameserver string
}

func New(nameserver string, timeout time.Duration) *Resolver {
	if strings.TrimSpace(nameserver) == "" {
		nameserver = "1.1.1.1:53"
	}
	return &Resolver{
		client: &dns.Client{Timeout: timeout},
		nameserver: nameserver,
	}
}

func (r *Resolver) Resolve(ctx context.Context, host string) DNSResult {
	result := DNSResult{Subdomain: strings.TrimSuffix(strings.ToLower(host), ".")}
	fqdn := dns.Fqdn(result.Subdomain)

	if cname, err := r.queryCNAME(ctx, fqdn); err == nil {
		result.CNAME = cname
	} else {
		result.Error = err.Error()
	}

	aIPs, errA := r.queryIPs(ctx, fqdn, dns.TypeA)
	aaaaIPs, errAAAA := r.queryIPs(ctx, fqdn, dns.TypeAAAA)
	result.IPs = append(result.IPs, aIPs...)
	result.IPs = append(result.IPs, aaaaIPs...)
	result.HasValidIP = len(result.IPs) > 0

	if !result.HasValidIP && result.Error == "" {
		if errA != nil {
			result.Error = errA.Error()
		}
		if errAAAA != nil && result.Error == "" {
			result.Error = errAAAA.Error()
		}
	}

	return result
}

func (r *Resolver) queryCNAME(ctx context.Context, fqdn string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeCNAME)

	resp, _, err := r.client.ExchangeContext(ctx, msg, r.nameserver)
	if err != nil {
		return "", fmt.Errorf("cname lookup failed: %w", err)
	}
	for _, ans := range resp.Answer {
		if rec, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(strings.ToLower(rec.Target), "."), nil
		}
	}
	return "", nil
}

func (r *Resolver) queryIPs(ctx context.Context, fqdn string, qType uint16) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qType)

	resp, _, err := r.client.ExchangeContext(ctx, msg, r.nameserver)
	if err != nil {
		return nil, fmt.Errorf("record lookup failed: %w", err)
	}

	ips := make([]string, 0)
	for _, ans := range resp.Answer {
		switch rec := ans.(type) {
		case *dns.A:
			ips = append(ips, rec.A.String())
		case *dns.AAAA:
			ips = append(ips, rec.AAAA.String())
		}
	}
	return ips, nil
}
