package scanner

import "time"

// Status indicates scanner verdict for a subdomain.
type Status string

const (
	StatusConfirmed Status = "CONFIRMED"
	StatusPotential Status = "POTENTIAL"
	StatusSafe      Status = "SAFE"
)

// Options controls scanner behavior.
type Options struct {
	Domain           string
	Threads          int
	OutputFile       string
	Timeout          time.Duration
	Silent           bool
	JSONOutput       bool
	Verbose          bool
	FingerprintsPath string
	RateLimit        int
}

// HTTPResponse stores probing response artifacts used for matching.
type HTTPResponse struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Body       string            `json:"body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// Result represents one scanned subdomain output record.
type Result struct {
	Subdomain      string   `json:"subdomain"`
	Status         Status   `json:"status"`
	Service        string   `json:"service,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	CNAME          string   `json:"cname,omitempty"`
	IPs            []string `json:"ips,omitempty"`
	HTTPStatusCode int      `json:"http_status_code,omitempty"`
	MatchedString  string   `json:"matched_string,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Report is the final scanning summary.
type Report struct {
	Domain      string    `json:"domain"`
	GeneratedAt time.Time `json:"generated_at"`
	WildcardDNS bool      `json:"wildcard_dns"`
	Total       int       `json:"total"`
	Confirmed   int       `json:"confirmed"`
	Potential   int       `json:"potential"`
	Safe        int       `json:"safe"`
	Results     []Result  `json:"results"`
}
