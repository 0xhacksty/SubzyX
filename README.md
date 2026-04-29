# SubTakerX

SubTakerX is a production-oriented Go CLI for identifying subdomain takeover risks by chaining:

1. Subdomain enumeration (via `subfinder` binary)
2. DNS resolution (`A`, `AAAA`, `CNAME` via `miekg/dns`)
3. Dangling CNAME candidate selection
4. Fingerprint-driven service matching
5. HTTP probing with retries (`retryablehttp`)
6. Confirmed vs potential verdicting

## Features

- Concurrent worker pool scanning (`--threads`)
- Fingerprint database loaded from `fingerprints.json`
- Wildcard DNS detection and false-positive reduction
- Rate limiting (`--rate-limit`) to reduce bans
- Timeout control (`--timeout`)
- Colored output and JSON mode
- Silent mode and verbose logging
- File output (`-o`)
- Basic unit tests for detection logic

## Requirements

- Go 1.21+
- `subfinder` installed and available in `PATH`

Install subfinder quickly:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Project Layout

```text
subzyx/
 ├── main.go
 ├── cmd/
 │    └── root.go
 ├── internal/
 │    ├── enum/
 │    ├── resolver/
 │    ├── scanner/
 │    ├── fingerprints/
 │    ├── output/
 │    └── utils/
 ├── go.mod
 └── fingerprints.json
```

## Build

```bash
go mod init subzyx
go mod tidy
go build -o subzyx
```

If `go.mod` already exists (as in this repository), run:

```bash
go mod tidy
go build -o subzyx
```

## Usage

```bash
./subzyx -d example.com
./subzyx -d example.com -t 100 -o results.txt
./subzyx -d example.com --json -o results.json
```

## CLI Flags

- `-d, --domain` target domain (required)
- `-t, --threads` concurrent workers (default `50`)
- `-o, --output` output file path
- `--timeout` HTTP timeout seconds (default `10`)
- `--silent` print only findings
- `--json` output structured JSON
- `--verbose` verbose logs
- `--rate-limit` HTTP request rate per second (default `20`)
- `--fingerprints` path to fingerprints file (default `fingerprints.json`)

## Example Output

```text
[CONFIRMED] app-old.example.com -> AWS S3 (CNAME and HTTP fingerprint matched)
[POTENTIAL] dev.example.com -> Heroku (CNAME matched known takeover-prone service)
[SAFE] www.example.com -> Unknown (No takeover indicators)
Summary: total=120 confirmed=1 potential=4 safe=115 wildcard_dns=false
```

## Detection Logic

- Confirmed: CNAME service match + HTTP fingerprint match
- Potential: partial match (CNAME only, body only, or dangling DNS without definitive signature)
- Safe: no takeover indicators

## Notes

- This tool assists security testing and triage; always manually validate before reporting critical findings.
- Fingerprints can be extended by editing `fingerprints.json`.
