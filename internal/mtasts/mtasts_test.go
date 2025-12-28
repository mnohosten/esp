package mtasts

import (
	"context"
	"testing"
	"time"
)

func TestPolicyModeConstants(t *testing.T) {
	tests := []struct {
		mode     PolicyMode
		expected string
	}{
		{PolicyModeEnforce, "enforce"},
		{PolicyModeTesting, "testing"},
		{PolicyModeNone, "none"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.expected {
			t.Errorf("Expected mode '%s', got '%s'", tt.expected, string(tt.mode))
		}
	}
}

func TestPolicy(t *testing.T) {
	policy := &Policy{
		Version: "STSv1",
		Mode:    "enforce",
		MX:      []string{"mail.example.com", "*.example.com"},
		MaxAge:  86400,
	}

	if policy.Version != "STSv1" {
		t.Errorf("Expected Version 'STSv1', got '%s'", policy.Version)
	}
	if policy.Mode != "enforce" {
		t.Errorf("Expected Mode 'enforce', got '%s'", policy.Mode)
	}
	if len(policy.MX) != 2 {
		t.Errorf("Expected 2 MX patterns, got %d", len(policy.MX))
	}
	if policy.MaxAge != 86400 {
		t.Errorf("Expected MaxAge 86400, got %d", policy.MaxAge)
	}
}

func TestCachedPolicy(t *testing.T) {
	now := time.Now()
	policy := &CachedPolicy{
		Domain:        "example.com",
		PolicyID:      "policy123",
		Mode:          string(PolicyModeEnforce),
		MXPatterns:    []string{"mail.example.com", "*.example.com"},
		MaxAge:        86400,
		FetchedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		LastValidated: now,
	}

	if policy.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got '%s'", policy.Domain)
	}
	if policy.Mode != "enforce" {
		t.Errorf("Expected Mode 'enforce', got '%s'", policy.Mode)
	}
}

func TestCachedPolicyIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: now.Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: now.Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "just expired",
			expiresAt: now.Add(-1 * time.Second),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &CachedPolicy{
				ExpiresAt: tt.expiresAt,
			}
			if policy.IsExpired() != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", policy.IsExpired(), tt.expected)
			}
		})
	}
}

func TestCachedPolicyIsEnforcing(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected bool
	}{
		{
			name:     "enforce mode",
			mode:     string(PolicyModeEnforce),
			expected: true,
		},
		{
			name:     "testing mode",
			mode:     string(PolicyModeTesting),
			expected: false,
		},
		{
			name:     "none mode",
			mode:     string(PolicyModeNone),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &CachedPolicy{Mode: tt.mode}
			if policy.IsEnforcing() != tt.expected {
				t.Errorf("IsEnforcing() = %v, want %v", policy.IsEnforcing(), tt.expected)
			}
		})
	}
}

func TestCachedPolicyIsTesting(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected bool
	}{
		{
			name:     "enforce mode",
			mode:     string(PolicyModeEnforce),
			expected: false,
		},
		{
			name:     "testing mode",
			mode:     string(PolicyModeTesting),
			expected: true,
		},
		{
			name:     "none mode",
			mode:     string(PolicyModeNone),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &CachedPolicy{Mode: tt.mode}
			if policy.IsTesting() != tt.expected {
				t.Errorf("IsTesting() = %v, want %v", policy.IsTesting(), tt.expected)
			}
		})
	}
}

func TestDNSRecord(t *testing.T) {
	record := &DNSRecord{
		Version:  "STSv1",
		ID:       "20240101T000000",
		RawValue: "v=STSv1; id=20240101T000000",
	}

	if record.Version != "STSv1" {
		t.Errorf("Expected Version 'STSv1', got '%s'", record.Version)
	}
	if record.ID != "20240101T000000" {
		t.Errorf("Expected ID '20240101T000000', got '%s'", record.ID)
	}
}

func TestValidatorValidateMX(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		mxHost     string
		policy     *CachedPolicy
		wantValid  bool
	}{
		{
			name:   "valid with enforce policy",
			mxHost: "mail.example.com",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeEnforce),
				MXPatterns: []string{"mail.example.com", "*.example.com"},
			},
			wantValid: true,
		},
		{
			name:   "valid with wildcard",
			mxHost: "mx1.example.com",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeEnforce),
				MXPatterns: []string{"*.example.com"},
			},
			wantValid: true,
		},
		{
			name:   "invalid - no match",
			mxHost: "mail.other.com",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeEnforce),
				MXPatterns: []string{"*.example.com"},
			},
			wantValid: false,
		},
		{
			name:      "nil policy",
			mxHost:    "mail.example.com",
			policy:    nil,
			wantValid: true,
		},
		{
			name:   "none mode always valid",
			mxHost: "mail.other.com",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeNone),
				MXPatterns: []string{"*.example.com"},
			},
			wantValid: true,
		},
		{
			name:   "case insensitive match",
			mxHost: "MAIL.EXAMPLE.COM",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeEnforce),
				MXPatterns: []string{"mail.example.com"},
			},
			wantValid: true,
		},
		{
			name:   "wildcard doesn't match subdomain",
			mxHost: "sub.mail.example.com",
			policy: &CachedPolicy{
				Mode:       string(PolicyModeEnforce),
				MXPatterns: []string{"*.example.com"},
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateMX(tt.mxHost, tt.policy)
			if result.Valid != tt.wantValid {
				t.Errorf("ValidateMX().Valid = %v, want %v", result.Valid, tt.wantValid)
			}
		})
	}
}

func TestValidationResult(t *testing.T) {
	result := &ValidationResult{
		Valid:       true,
		MXHost:      "mail.example.com",
		MatchedRule: "mail.example.com",
		Error:       "",
	}

	if !result.Valid {
		t.Error("Expected Valid to be true")
	}
	if result.MatchedRule != "mail.example.com" {
		t.Errorf("Expected MatchedRule 'mail.example.com', got '%s'", result.MatchedRule)
	}
}

func TestValidatorValidateAllMX(t *testing.T) {
	validator := NewValidator()
	policy := &CachedPolicy{
		Mode:       string(PolicyModeEnforce),
		MXPatterns: []string{"*.example.com"},
	}

	mxHosts := []string{"mx1.example.com", "mx2.example.com", "mx.other.com"}
	results := validator.ValidateAllMX(mxHosts, policy)

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// First two should be valid
	if !results[0].Valid {
		t.Error("Expected mx1.example.com to be valid")
	}
	if !results[1].Valid {
		t.Error("Expected mx2.example.com to be valid")
	}
	// Third should be invalid
	if results[2].Valid {
		t.Error("Expected mx.other.com to be invalid")
	}
}

func TestValidatorHasValidMX(t *testing.T) {
	validator := NewValidator()
	policy := &CachedPolicy{
		Mode:       string(PolicyModeEnforce),
		MXPatterns: []string{"*.example.com"},
	}

	// With at least one valid MX
	mxHosts1 := []string{"mx.other.com", "mx1.example.com"}
	if !validator.HasValidMX(mxHosts1, policy) {
		t.Error("Expected HasValidMX to return true")
	}

	// With no valid MX
	mxHosts2 := []string{"mx.other.com", "mx.another.org"}
	if validator.HasValidMX(mxHosts2, policy) {
		t.Error("Expected HasValidMX to return false")
	}
}

func TestFetcherConfig(t *testing.T) {
	config := FetcherConfig{
		Timeout: 30 * time.Second,
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout 30s, got %v", config.Timeout)
	}
}

func TestCacheConfig(t *testing.T) {
	config := CacheConfig{
		MemoryTTL: 5 * time.Minute,
	}

	if config.MemoryTTL != 5*time.Minute {
		t.Errorf("Expected MemoryTTL 5m, got %v", config.MemoryTTL)
	}
}

func TestManagerConfig(t *testing.T) {
	config := ManagerConfig{
		Enabled:         true,
		FetchTimeout:    30 * time.Second,
		MemoryCacheTTL:  5 * time.Minute,
		RefreshInterval: 1 * time.Hour,
	}

	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if config.FetchTimeout != 30*time.Second {
		t.Errorf("Expected FetchTimeout 30s, got %v", config.FetchTimeout)
	}
}

func TestFetchResult(t *testing.T) {
	now := time.Now()
	result := &FetchResult{
		Policy: &Policy{
			Version: "STSv1",
			Mode:    "enforce",
			MX:      []string{"mail.example.com"},
			MaxAge:  86400,
		},
		PolicyID:  "20240101T000000",
		FetchedAt: now,
		NotFound:  false,
	}

	if result.NotFound {
		t.Error("Expected NotFound to be false")
	}
	if result.Policy.Mode != "enforce" {
		t.Errorf("Expected Mode 'enforce', got '%s'", result.Policy.Mode)
	}
}

func TestFetchResultNotFound(t *testing.T) {
	result := &FetchResult{
		NotFound: true,
		DNSError: true,
	}

	if !result.NotFound {
		t.Error("Expected NotFound to be true")
	}
	if !result.DNSError {
		t.Error("Expected DNSError to be true")
	}
}

func TestFetchResultHTTPError(t *testing.T) {
	result := &FetchResult{
		HTTPError: true,
	}

	if !result.HTTPError {
		t.Error("Expected HTTPError to be true")
	}
}

func TestFetchResultParseError(t *testing.T) {
	result := &FetchResult{
		ParseError: true,
	}

	if !result.ParseError {
		t.Error("Expected ParseError to be true")
	}
}

// Test context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled")
	}
}

func TestValidatorWithTrailingDot(t *testing.T) {
	validator := NewValidator()
	policy := &CachedPolicy{
		Mode:       string(PolicyModeEnforce),
		MXPatterns: []string{"mail.example.com"},
	}

	// MX host with trailing dot (common in DNS)
	result := validator.ValidateMX("mail.example.com.", policy)
	if !result.Valid {
		t.Error("Expected MX with trailing dot to be valid")
	}
}

func TestPolicyModeStrings(t *testing.T) {
	// Test that policy mode values match expected strings
	if PolicyModeEnforce != "enforce" {
		t.Errorf("Expected PolicyModeEnforce to be 'enforce', got '%s'", PolicyModeEnforce)
	}
	if PolicyModeTesting != "testing" {
		t.Errorf("Expected PolicyModeTesting to be 'testing', got '%s'", PolicyModeTesting)
	}
	if PolicyModeNone != "none" {
		t.Errorf("Expected PolicyModeNone to be 'none', got '%s'", PolicyModeNone)
	}
}
