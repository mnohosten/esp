package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReportJSONParsing(t *testing.T) {
	jsonData := `{
		"organization-name": "Test Org",
		"date-range": {
			"start-datetime": "2024-01-01T00:00:00Z",
			"end-datetime": "2024-01-02T00:00:00Z"
		},
		"contact-info": "mailto:tlsrpt@test.org",
		"report-id": "test-report-123",
		"policies": [
			{
				"policy": {
					"policy-type": "sts",
					"policy-string": ["mode: enforce", "mx: mail.test.org"],
					"policy-domain": "test.org"
				},
				"summary": {
					"total-successful-session-count": 100,
					"total-failure-session-count": 5
				},
				"failure-details": [
					{
						"result-type": "certificate-expired",
						"sending-mta-ip": "192.0.2.1",
						"receiving-mx-hostname": "mail.test.org",
						"failed-session-count": 5
					}
				]
			}
		]
	}`

	var report Report
	err := json.Unmarshal([]byte(jsonData), &report)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if report.OrganizationName != "Test Org" {
		t.Errorf("Expected organization-name 'Test Org', got '%s'", report.OrganizationName)
	}
	if report.ReportID != "test-report-123" {
		t.Errorf("Expected report-id 'test-report-123', got '%s'", report.ReportID)
	}
	if len(report.Policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(report.Policies))
	}

	policy := report.Policies[0]
	if policy.Policy.PolicyType != "sts" {
		t.Errorf("Expected policy-type 'sts', got '%s'", policy.Policy.PolicyType)
	}
	if policy.Summary.TotalSuccessfulSessionCount != 100 {
		t.Errorf("Expected 100 successful sessions, got %d", policy.Summary.TotalSuccessfulSessionCount)
	}
	if policy.Summary.TotalFailureSessionCount != 5 {
		t.Errorf("Expected 5 failed sessions, got %d", policy.Summary.TotalFailureSessionCount)
	}
	if len(policy.FailureDetails) != 1 {
		t.Fatalf("Expected 1 failure detail, got %d", len(policy.FailureDetails))
	}
	if policy.FailureDetails[0].ResultType != "certificate-expired" {
		t.Errorf("Expected result-type 'certificate-expired', got '%s'", policy.FailureDetails[0].ResultType)
	}
}

func TestReportJSONGeneration(t *testing.T) {
	report := &Report{
		OrganizationName: "Test Generator",
		DateRange: DateRange{
			StartDateTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			EndDateTime:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		ContactInfo: "mailto:test@example.com",
		ReportID:    "gen-test-456",
		Policies: []PolicyResult{
			{
				Policy: Policy{
					PolicyType:   PolicyTypeSTS,
					PolicyString: []string{"mode: testing", "mx: *.example.com"},
					PolicyDomain: "example.com",
				},
				Summary: Summary{
					TotalSuccessfulSessionCount: 50,
					TotalFailureSessionCount:    2,
				},
				FailureDetails: []FailureDetail{
					{
						ResultType:          ResultTypeSTARTTLSNotSupported,
						SendingMTAIP:        "10.0.0.1",
						ReceivingMXHostname: "mx1.example.com",
						FailedSessionCount:  2,
					},
				},
			},
		},
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Parse it back
	var parsed Report
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal generated JSON: %v", err)
	}

	if parsed.OrganizationName != report.OrganizationName {
		t.Errorf("Round-trip failed for OrganizationName")
	}
	if parsed.ReportID != report.ReportID {
		t.Errorf("Round-trip failed for ReportID")
	}
	if len(parsed.Policies) != len(report.Policies) {
		t.Errorf("Round-trip failed for Policies count")
	}
}

func TestParserGzipDecompression(t *testing.T) {
	jsonData := `{
		"organization-name": "Gzip Test",
		"date-range": {
			"start-datetime": "2024-01-01T00:00:00Z",
			"end-datetime": "2024-01-02T00:00:00Z"
		},
		"report-id": "gzip-123",
		"policies": [
			{
				"policy": {
					"policy-type": "no-policy-found",
					"policy-domain": "test.com"
				},
				"summary": {
					"total-successful-session-count": 1,
					"total-failure-session-count": 0
				}
			}
		]
	}`

	// Compress with gzip
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to gzip: %v", err)
	}
	gw.Close()

	// Parse using ParseFromGzip
	parser := &Parser{}
	report, err := parser.ParseFromGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to parse gzipped report: %v", err)
	}

	if report.OrganizationName != "Gzip Test" {
		t.Errorf("Expected organization-name 'Gzip Test', got '%s'", report.OrganizationName)
	}
}

func TestParserIsReport(t *testing.T) {
	parser := &Parser{}

	tests := []struct {
		name        string
		contentType string
		subject     string
		from        string
		expected    bool
	}{
		{
			name:        "TLS-RPT JSON content type",
			contentType: "application/tlsrpt+json",
			subject:     "",
			from:        "",
			expected:    true,
		},
		{
			name:        "TLS-RPT gzip content type",
			contentType: "application/tlsrpt+gzip",
			subject:     "",
			from:        "",
			expected:    true,
		},
		{
			name:        "TLS-RPT by subject",
			contentType: "application/json",
			subject:     "TLS-RPT report for example.com",
			from:        "",
			expected:    true,
		},
		{
			name:        "TLS-RPT by from address",
			contentType: "text/plain",
			subject:     "Report",
			from:        "tlsrpt@example.com",
			expected:    true,
		},
		{
			name:        "Not a TLS-RPT report",
			contentType: "text/plain",
			subject:     "Hello World",
			from:        "user@example.com",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.IsReport(tt.contentType, tt.subject, tt.from)
			if result != tt.expected {
				t.Errorf("IsReport(%q, %q, %q) = %v, want %v",
					tt.contentType, tt.subject, tt.from, result, tt.expected)
			}
		})
	}
}

func TestResultTypeConstants(t *testing.T) {
	tests := []struct {
		resultType string
		expected   string
	}{
		{ResultTypeSuccess, "success"},
		{ResultTypeSTARTTLSNotSupported, "starttls-not-supported"},
		{ResultTypeCertificateHostMismatch, "certificate-host-mismatch"},
		{ResultTypeCertificateExpired, "certificate-expired"},
		{ResultTypeCertificateNotTrusted, "certificate-not-trusted"},
		{ResultTypeTLSAInvalid, "tlsa-invalid"},
		{ResultTypeDNSSECInvalid, "dnssec-invalid"},
		{ResultTypeSTSPolicyInvalid, "sts-policy-invalid"},
		{ResultTypeSTSPolicyFetchError, "sts-policy-fetch-error"},
		{ResultTypeSTSWebPKIInvalid, "sts-webpki-invalid"},
		{ResultTypeValidationFailure, "validation-failure"},
	}

	for _, tt := range tests {
		if tt.resultType != tt.expected {
			t.Errorf("Expected result type '%s', got '%s'", tt.expected, tt.resultType)
		}
	}
}

func TestPolicyTypeConstants(t *testing.T) {
	tests := []struct {
		policyType string
		expected   string
	}{
		{PolicyTypeSTS, "sts"},
		{PolicyTypeTLSA, "tlsa"},
		{PolicyTypeNoPolicyFound, "no-policy-found"},
	}

	for _, tt := range tests {
		if tt.policyType != tt.expected {
			t.Errorf("Expected policy type '%s', got '%s'", tt.expected, tt.policyType)
		}
	}
}

func TestConnectionResult(t *testing.T) {
	result := &ConnectionResult{
		ID:              uuid.New(),
		RecipientDomain: "example.com",
		MXHost:          "mx1.example.com",
		PolicyType:      PolicyTypeSTS,
		PolicyDomain:    "example.com",
		PolicyString:    []string{"mode: enforce"},
		ResultType:      ResultTypeSuccess,
		Success:         true,
		TLSVersion:      "TLSv1.3",
		CipherSuite:     "TLS_AES_128_GCM_SHA256",
		CertIssuer:      "Let's Encrypt",
		CertSubject:     "*.example.com",
		CertExpiry:      time.Now().Add(90 * 24 * time.Hour),
		CreatedAt:       time.Now(),
	}

	if result.RecipientDomain != "example.com" {
		t.Errorf("Expected RecipientDomain 'example.com', got '%s'", result.RecipientDomain)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.TLSVersion != "TLSv1.3" {
		t.Errorf("Expected TLSVersion 'TLSv1.3', got '%s'", result.TLSVersion)
	}
}

func TestConnectionResultFailure(t *testing.T) {
	result := &ConnectionResult{
		ID:                uuid.New(),
		RecipientDomain:   "failed.com",
		MXHost:            "mx.failed.com",
		PolicyType:        PolicyTypeNoPolicyFound,
		ResultType:        ResultTypeCertificateExpired,
		Success:           false,
		FailureReasonText: "certificate has expired",
		CreatedAt:         time.Now(),
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.ResultType != ResultTypeCertificateExpired {
		t.Errorf("Expected ResultType 'certificate-expired', got '%s'", result.ResultType)
	}
}

func TestReportFilter(t *testing.T) {
	filter := ReportFilter{
		Domain:   "example.com",
		DateFrom: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateTo:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		Status:   ReportStatusPending,
	}

	if filter.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got '%s'", filter.Domain)
	}
	if filter.Status != ReportStatusPending {
		t.Errorf("Expected Status 'pending', got '%s'", filter.Status)
	}
}

func TestReportStatusConstants(t *testing.T) {
	tests := []struct {
		status   string
		expected string
	}{
		{ReportStatusPending, "pending"},
		{ReportStatusSent, "sent"},
		{ReportStatusFailed, "failed"},
	}

	for _, tt := range tests {
		if tt.status != tt.expected {
			t.Errorf("Expected status '%s', got '%s'", tt.expected, tt.status)
		}
	}
}

func TestReceivedReport(t *testing.T) {
	report := &ReceivedReport{
		ID:               uuid.New(),
		OrganizationName: "Test Org",
		ContactInfo:      "mailto:tlsrpt@test.org",
		ReportID:         "recv-123",
		DateRangeStart:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateRangeEnd:     time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		PolicyDomain:     "test.org",
		TotalSuccessful:  100,
		TotalFailed:      5,
		ReceivedAt:       time.Now(),
	}

	if report.OrganizationName != "Test Org" {
		t.Errorf("Expected OrganizationName 'Test Org', got '%s'", report.OrganizationName)
	}
	if report.TotalSuccessful != 100 {
		t.Errorf("Expected TotalSuccessful 100, got %d", report.TotalSuccessful)
	}
}

func TestSentReport(t *testing.T) {
	report := &SentReport{
		ID:             uuid.New(),
		PolicyDomain:   "example.com",
		RUAURI:         "mailto:tlsrpt@example.com",
		DateRangeStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateRangeEnd:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		ReportID:       "sent-456",
		Status:         ReportStatusPending,
		CreatedAt:      time.Now(),
	}

	if report.PolicyDomain != "example.com" {
		t.Errorf("Expected PolicyDomain 'example.com', got '%s'", report.PolicyDomain)
	}
	if report.Status != ReportStatusPending {
		t.Errorf("Expected Status 'pending', got '%s'", report.Status)
	}
}

func TestTLSStats(t *testing.T) {
	stats := &TLSStats{
		Period:           "2024-01-01 to 2024-01-07",
		TotalConnections: 1000,
		Successful:       950,
		Failed:           50,
		SuccessRate:      95.0,
		ByResultType: map[string]int{
			"success":              950,
			"certificate-expired":  30,
			"starttls-not-supported": 20,
		},
		ByPolicyType: map[string]int{
			"sts":             600,
			"no-policy-found": 400,
		},
		TopFailingDomains: []DomainStats{
			{Domain: "failing.com", Total: 100, Successful: 70, Failed: 30, FailRate: 30.0},
		},
	}

	if stats.SuccessRate != 95.0 {
		t.Errorf("Expected SuccessRate 95.0, got %f", stats.SuccessRate)
	}
	if stats.TotalConnections != 1000 {
		t.Errorf("Expected TotalConnections 1000, got %d", stats.TotalConnections)
	}
	if len(stats.TopFailingDomains) != 1 {
		t.Errorf("Expected 1 top failing domain, got %d", len(stats.TopFailingDomains))
	}
}

func TestTrackerConfig(t *testing.T) {
	config := TrackerConfig{
		Enabled:   true,
		BatchSize: 50,
	}

	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if config.BatchSize != 50 {
		t.Errorf("Expected BatchSize 50, got %d", config.BatchSize)
	}
}

func TestWorkerConfig(t *testing.T) {
	config := WorkerConfig{
		Enabled:    true,
		ReportTime: "03:00",
		MaxRetries: 3,
		CleanupAge: 30 * 24 * time.Hour,
		RetryIntervals: []time.Duration{
			5 * time.Minute,
			15 * time.Minute,
		},
	}

	if config.ReportTime != "03:00" {
		t.Errorf("Expected ReportTime '03:00', got '%s'", config.ReportTime)
	}
	if config.CleanupAge != 30*24*time.Hour {
		t.Errorf("Expected CleanupAge 30 days, got %v", config.CleanupAge)
	}
}

func TestGeneratorConfig(t *testing.T) {
	config := GeneratorConfig{
		Hostname:    "mail.example.com",
		OrgName:     "Example Org",
		ContactInfo: "mailto:postmaster@example.com",
	}

	if config.Hostname != "mail.example.com" {
		t.Errorf("Expected Hostname 'mail.example.com', got '%s'", config.Hostname)
	}
	if config.OrgName != "Example Org" {
		t.Errorf("Expected OrgName 'Example Org', got '%s'", config.OrgName)
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLSv1.0"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS13, "TLSv1.3"},
		{0x0000, "0x0000"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(%#x) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

func TestClassifyTLSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: ResultTypeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyTLSError(tt.err)
			if result != tt.expected {
				t.Errorf("classifyTLSError() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// Benchmark JSON parsing
func BenchmarkJSONParsing(b *testing.B) {
	jsonData := `{
		"organization-name": "Benchmark Org",
		"date-range": {
			"start-datetime": "2024-01-01T00:00:00Z",
			"end-datetime": "2024-01-02T00:00:00Z"
		},
		"report-id": "bench-123",
		"policies": [
			{
				"policy": {
					"policy-type": "sts",
					"policy-string": ["mode: enforce"],
					"policy-domain": "bench.com"
				},
				"summary": {
					"total-successful-session-count": 1000,
					"total-failure-session-count": 10
				}
			}
		]
	}`

	data := []byte(jsonData)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var report Report
		json.Unmarshal(data, &report)
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

func TestDateRangeParsing(t *testing.T) {
	jsonData := `{
		"start-datetime": "2024-01-15T12:30:00Z",
		"end-datetime": "2024-01-16T12:30:00Z"
	}`

	var dr DateRange
	err := json.Unmarshal([]byte(jsonData), &dr)
	if err != nil {
		t.Fatalf("Failed to parse DateRange: %v", err)
	}

	expected := time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC)
	if !dr.StartDateTime.Equal(expected) {
		t.Errorf("Expected StartDateTime %v, got %v", expected, dr.StartDateTime)
	}
}

func TestPolicyResultWithMultipleFailures(t *testing.T) {
	result := PolicyResult{
		Policy: Policy{
			PolicyType:   PolicyTypeSTS,
			PolicyString: []string{"mode: enforce", "mx: *.example.com"},
			PolicyDomain: "example.com",
		},
		Summary: Summary{
			TotalSuccessfulSessionCount: 100,
			TotalFailureSessionCount:    10,
		},
		FailureDetails: []FailureDetail{
			{
				ResultType:          ResultTypeCertificateExpired,
				SendingMTAIP:        "10.0.0.1",
				ReceivingMXHostname: "mx1.example.com",
				FailedSessionCount:  5,
			},
			{
				ResultType:          ResultTypeSTARTTLSNotSupported,
				SendingMTAIP:        "10.0.0.2",
				ReceivingMXHostname: "mx2.example.com",
				FailedSessionCount:  5,
			},
		},
	}

	if len(result.FailureDetails) != 2 {
		t.Errorf("Expected 2 failure details, got %d", len(result.FailureDetails))
	}

	totalFailed := 0
	for _, fd := range result.FailureDetails {
		totalFailed += fd.FailedSessionCount
	}
	if totalFailed != result.Summary.TotalFailureSessionCount {
		t.Errorf("Sum of failure details (%d) doesn't match total (%d)",
			totalFailed, result.Summary.TotalFailureSessionCount)
	}
}

func TestDailyAggregate(t *testing.T) {
	agg := &DailyAggregate{
		ID:              uuid.New(),
		ReportDate:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		RecipientDomain: "example.com",
		PolicyType:      PolicyTypeSTS,
		PolicyDomain:    "example.com",
		TotalSuccessful: 100,
		TotalFailed:     5,
		FailureDetails: map[string]int{
			"certificate-expired":    3,
			"starttls-not-supported": 2,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if agg.TotalSuccessful != 100 {
		t.Errorf("Expected TotalSuccessful 100, got %d", agg.TotalSuccessful)
	}
	if len(agg.FailureDetails) != 2 {
		t.Errorf("Expected 2 failure detail types, got %d", len(agg.FailureDetails))
	}
}

func TestDomainStats(t *testing.T) {
	stats := DomainStats{
		Domain:     "example.com",
		Total:      100,
		Successful: 95,
		Failed:     5,
		FailRate:   5.0,
	}

	if stats.FailRate != 5.0 {
		t.Errorf("Expected FailRate 5.0, got %f", stats.FailRate)
	}
	if stats.Successful+stats.Failed != stats.Total {
		t.Error("Successful + Failed should equal Total")
	}
}

func TestDNSRecord(t *testing.T) {
	record := DNSRecord{
		Version: "TLSRPTv1",
		RUA:     []string{"mailto:tlsrpt@example.com", "https://reports.example.com/tlsrpt"},
	}

	if record.Version != "TLSRPTv1" {
		t.Errorf("Expected Version 'TLSRPTv1', got '%s'", record.Version)
	}
	if len(record.RUA) != 2 {
		t.Errorf("Expected 2 RUA addresses, got %d", len(record.RUA))
	}
}
