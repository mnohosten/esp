package mtasts

import (
	"strings"
)

// Validator validates MX hosts against MTA-STS policies.
type Validator struct{}

// NewValidator creates a new MTA-STS validator.
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateMX checks if an MX host is allowed by the policy.
func (v *Validator) ValidateMX(mxHost string, policy *CachedPolicy) *ValidationResult {
	if policy == nil {
		return &ValidationResult{
			Valid:  true,
			MXHost: mxHost,
		}
	}

	// Mode "none" allows everything
	if policy.Mode == string(PolicyModeNone) {
		return &ValidationResult{
			Valid:  true,
			MXHost: mxHost,
		}
	}

	mxHost = strings.ToLower(strings.TrimSuffix(mxHost, "."))

	for _, pattern := range policy.MXPatterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if v.matchPattern(mxHost, pattern) {
			return &ValidationResult{
				Valid:       true,
				MXHost:      mxHost,
				MatchedRule: pattern,
			}
		}
	}

	return &ValidationResult{
		Valid:  false,
		MXHost: mxHost,
		Error:  "MX host not in policy",
	}
}

// matchPattern checks if a hostname matches an MTA-STS MX pattern.
// Patterns can be:
// - Exact match: "mail.example.com"
// - Wildcard prefix: "*.example.com" (matches any subdomain)
func (v *Validator) matchPattern(hostname, pattern string) bool {
	if pattern == hostname {
		return true
	}

	// Wildcard pattern
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove "*", keep "."
		// The hostname must end with the suffix and have at least one character before
		if strings.HasSuffix(hostname, suffix) {
			prefix := hostname[:len(hostname)-len(suffix)]
			// Prefix should not contain dots (single-level wildcard only)
			return !strings.Contains(prefix, ".")
		}
	}

	return false
}

// ValidateAllMX validates a list of MX hosts against a policy.
func (v *Validator) ValidateAllMX(mxHosts []string, policy *CachedPolicy) []ValidationResult {
	results := make([]ValidationResult, len(mxHosts))
	for i, mx := range mxHosts {
		results[i] = *v.ValidateMX(mx, policy)
	}
	return results
}

// HasValidMX returns true if at least one MX host is valid according to the policy.
func (v *Validator) HasValidMX(mxHosts []string, policy *CachedPolicy) bool {
	for _, mx := range mxHosts {
		if v.ValidateMX(mx, policy).Valid {
			return true
		}
	}
	return false
}
