// Package mtasts implements MTA-STS (RFC 8461) policy fetching and validation.
package mtasts

import (
	"time"

	"github.com/google/uuid"
)

// Policy represents an MTA-STS policy.
type Policy struct {
	Version string   `json:"version"` // "STSv1"
	Mode    string   `json:"mode"`    // "enforce", "testing", "none"
	MX      []string `json:"mx"`      // MX patterns (e.g., "*.example.com", "mail.example.com")
	MaxAge  int      `json:"max_age"` // Policy lifetime in seconds
}

// PolicyMode represents the MTA-STS policy mode.
type PolicyMode string

const (
	PolicyModeEnforce PolicyMode = "enforce"
	PolicyModeTesting PolicyMode = "testing"
	PolicyModeNone    PolicyMode = "none"
)

// CachedPolicy includes metadata for caching.
type CachedPolicy struct {
	ID              uuid.UUID `json:"id"`
	Domain          string    `json:"domain"`
	PolicyID        string    `json:"policy_id"`
	Mode            string    `json:"mode"`
	MXPatterns      []string  `json:"mx_patterns"`
	MaxAge          int       `json:"max_age"`
	FetchedAt       time.Time `json:"fetched_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	LastValidated   time.Time `json:"last_validated"`
	ValidationError string    `json:"validation_error,omitempty"`
	FetchFailures   int       `json:"fetch_failures"`
}

// IsExpired returns true if the policy has expired.
func (p *CachedPolicy) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// IsEnforcing returns true if the policy is in enforce mode.
func (p *CachedPolicy) IsEnforcing() bool {
	return p.Mode == string(PolicyModeEnforce)
}

// IsTesting returns true if the policy is in testing mode.
func (p *CachedPolicy) IsTesting() bool {
	return p.Mode == string(PolicyModeTesting)
}

// DNSRecord represents the MTA-STS DNS TXT record.
type DNSRecord struct {
	Version  string `json:"version"`   // "STSv1"
	ID       string `json:"id"`        // Policy ID for change detection
	RawValue string `json:"raw_value"` // Original TXT record value
}

// FetchResult represents the result of fetching a policy.
type FetchResult struct {
	Policy     *Policy
	PolicyID   string
	FetchedAt  time.Time
	Error      error
	NotFound   bool // True if domain has no MTA-STS policy
	DNSError   bool // True if DNS lookup failed
	HTTPError  bool // True if HTTP fetch failed
	ParseError bool // True if policy parsing failed
}

// ValidationResult represents the result of validating an MX host against a policy.
type ValidationResult struct {
	Valid       bool   `json:"valid"`
	MXHost      string `json:"mx_host"`
	MatchedRule string `json:"matched_rule,omitempty"`
	Error       string `json:"error,omitempty"`
}
