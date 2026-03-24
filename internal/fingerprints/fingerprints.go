package fingerprints

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ServiceFingerprint maps DNS and HTTP fingerprints to a takeover-prone service.
type ServiceFingerprint struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Vulnerable  bool     `json:"vulnerable"`
}

// Store is a runtime in-memory collection of service fingerprints.
type Store struct {
	Entries []ServiceFingerprint
}

func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprints file: %w", err)
	}
	var entries []ServiceFingerprint
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse fingerprints json: %w", err)
	}
	return &Store{Entries: entries}, nil
}

func NewFromEntries(entries []ServiceFingerprint) *Store {
	return &Store{Entries: entries}
}

func (s *Store) MatchByCNAME(cname string) []ServiceFingerprint {
	cname = strings.ToLower(cname)
	matched := make([]ServiceFingerprint, 0)
	for _, entry := range s.Entries {
		for _, token := range entry.CNAME {
			if strings.Contains(cname, strings.ToLower(token)) {
				matched = append(matched, entry)
				break
			}
		}
	}
	return matched
}

func (s *Store) MatchBody(body string, candidates []ServiceFingerprint) (bool, string, string) {
	bodyLower := strings.ToLower(body)
	for _, entry := range candidates {
		for _, fp := range entry.Fingerprint {
			if strings.Contains(bodyLower, strings.ToLower(fp)) {
				return true, entry.Service, fp
			}
		}
	}
	return false, "", ""
}

func (s *Store) MatchBodyAny(body string) (bool, string, string) {
	return s.MatchBody(body, s.Entries)
}
