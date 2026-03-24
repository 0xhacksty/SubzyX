package scanner

import (
	"testing"

	"subzyx/internal/fingerprints"
	"subzyx/internal/resolver"
)

func TestEvaluateCandidateConfirmed(t *testing.T) {
	store := fingerprints.NewFromEntries([]fingerprints.ServiceFingerprint{
		{
			Service:     "AWS S3",
			CNAME:       []string{"s3.amazonaws.com"},
			Fingerprint: []string{"NoSuchBucket"},
			Vulnerable:  true,
		},
	})

	in := probedCandidate{
		DNSResult: resolver.DNSResult{
			Subdomain:  "test.example.com",
			CNAME:      "missing-bucket.s3.amazonaws.com",
			IPs:        nil,
			HasValidIP: false,
		},
		Response: &HTTPResponse{
			StatusCode: 404,
			Body:       "NoSuchBucket: The specified bucket does not exist",
		},
	}

	got := EvaluateCandidate(in, store, "example.com")
	if got.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %s", got.Status)
	}
	if got.Service != "AWS S3" {
		t.Fatalf("expected AWS S3 service, got %s", got.Service)
	}
}

func TestEvaluateCandidatePotential(t *testing.T) {
	store := fingerprints.NewFromEntries([]fingerprints.ServiceFingerprint{
		{
			Service:     "Heroku",
			CNAME:       []string{"herokudns.com"},
			Fingerprint: []string{"No such app"},
			Vulnerable:  true,
		},
	})

	in := probedCandidate{
		DNSResult: resolver.DNSResult{
			Subdomain:  "dev.example.com",
			CNAME:      "foo.herokudns.com",
			IPs:        []string{"203.0.113.10"},
			HasValidIP: true,
		},
		Response: &HTTPResponse{
			StatusCode: 200,
			Body:       "Welcome",
		},
	}

	got := EvaluateCandidate(in, store, "example.com")
	if got.Status != StatusPotential {
		t.Fatalf("expected potential, got %s", got.Status)
	}
	if got.Service != "Heroku" {
		t.Fatalf("expected Heroku service, got %s", got.Service)
	}
}
