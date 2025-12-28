package dmarc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"net"
	"testing"
	"time"
)

func TestAggregateReportXMLParsing(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Google Inc.</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range>
      <begin>1234567890</begin>
      <end>1234654290</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
        <selector>default</selector>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

	var report AggregateReport
	err := xml.Unmarshal([]byte(xmlData), &report)
	if err != nil {
		t.Fatalf("Failed to parse XML: %v", err)
	}

	// Verify report metadata
	if report.ReportMetadata.OrgName != "Google Inc." {
		t.Errorf("Expected org_name 'Google Inc.', got '%s'", report.ReportMetadata.OrgName)
	}
	if report.ReportMetadata.ReportID != "12345678901234567890" {
		t.Errorf("Expected report_id '12345678901234567890', got '%s'", report.ReportMetadata.ReportID)
	}

	// Verify policy published
	if report.PolicyPublished.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", report.PolicyPublished.Domain)
	}
	if report.PolicyPublished.Policy != "reject" {
		t.Errorf("Expected policy 'reject', got '%s'", report.PolicyPublished.Policy)
	}

	// Verify records
	if len(report.Records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(report.Records))
	}

	record := report.Records[0]
	if record.Row.SourceIP != "192.0.2.1" {
		t.Errorf("Expected source_ip '192.0.2.1', got '%s'", record.Row.SourceIP)
	}
	if record.Row.Count != 10 {
		t.Errorf("Expected count 10, got %d", record.Row.Count)
	}
	if record.Row.PolicyEvaluated.DKIM != "pass" {
		t.Errorf("Expected DKIM 'pass', got '%s'", record.Row.PolicyEvaluated.DKIM)
	}
}

func TestAggregateReportXMLGeneration(t *testing.T) {
	report := &AggregateReport{
		ReportMetadata: ReportMetadata{
			OrgName:   "Test Org",
			Email:     "dmarc@test.org",
			ReportID:  "test-report-123",
			DateRange: DateRange{Begin: 1700000000, End: 1700086400},
		},
		PolicyPublished: PolicyPublished{
			Domain:          "example.com",
			ADKIM:           "r",
			ASPF:            "r",
			Policy:          "quarantine",
			SubdomainPolicy: "none",
			Percentage:      100,
			FailureOptions:  "0",
		},
		Records: []Record{
			{
				Row: Row{
					SourceIP: "10.0.0.1",
					Count:    5,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: "none",
						DKIM:        "pass",
						SPF:         "pass",
					},
				},
				Identifiers: Identifiers{
					HeaderFrom: "example.com",
				},
				AuthResults: AuthResults{
					DKIM: []DKIMAuthResult{
						{Domain: "example.com", Result: "pass", Selector: "s1"},
					},
					SPF: []SPFAuthResult{
						{Domain: "example.com", Result: "pass", Scope: "mfrom"},
					},
				},
			},
		},
	}

	xmlData, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal XML: %v", err)
	}

	// Parse it back
	var parsed AggregateReport
	err = xml.Unmarshal(xmlData, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal generated XML: %v", err)
	}

	if parsed.ReportMetadata.OrgName != report.ReportMetadata.OrgName {
		t.Errorf("Round-trip failed for OrgName")
	}
	if parsed.PolicyPublished.Domain != report.PolicyPublished.Domain {
		t.Errorf("Round-trip failed for Domain")
	}
	if len(parsed.Records) != len(report.Records) {
		t.Errorf("Round-trip failed for Records count")
	}
}

func TestParserGzipDecompression(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Test</org_name>
    <email>test@test.com</email>
    <report_id>123</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>test.com</domain>
    <p>none</p>
  </policy_published>
</feedback>`

	// Compress with gzip
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte(xmlData))
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

	if report.ReportMetadata.OrgName != "Test" {
		t.Errorf("Expected org_name 'Test', got '%s'", report.ReportMetadata.OrgName)
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
			name:        "DMARC report by content type",
			contentType: "application/zip",
			subject:     "Report Domain: example.com",
			from:        "noreply@google.com",
			expected:    true,
		},
		{
			name:        "DMARC report by gzip content type",
			contentType: "application/gzip",
			subject:     "DMARC Aggregate Report",
			from:        "dmarc@yahoo.com",
			expected:    true,
		},
		{
			name:        "DMARC report by subject pattern",
			contentType: "multipart/mixed",
			subject:     "Report domain: test.com Submitter: google.com",
			from:        "postmaster@mail.com",
			expected:    true,
		},
		{
			name:        "Not a DMARC report",
			contentType: "text/plain",
			subject:     "Hello World",
			from:        "user@example.com",
			expected:    false,
		},
		{
			name:        "DMARC report from known sender",
			contentType: "text/plain",
			subject:     "Some subject",
			from:        "noreply-dmarc-support@google.com",
			expected:    true,
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

func TestAuthResultTypes(t *testing.T) {
	// Test AuthResult struct with actual fields from types.go
	ar := &AuthResult{
		HeaderFromDomain:   "example.com",
		EnvelopeFromDomain: "example.com",
		EnvelopeToDomain:   "recipient.com",
		SourceIP:           net.ParseIP("192.168.1.1"),
		SPFResult:          "pass",
		SPFDomain:          "example.com",
		SPFAligned:         true,
		DKIMResults: []DKIMResultJSON{
			{Domain: "example.com", Selector: "default", Result: "pass", Aligned: true},
		},
		DKIMAligned: true,
		DMARCResult: "pass",
		DMARCPolicy: "reject",
		Disposition: "none",
		ReceivedAt:  time.Now(),
		ReportDate:  time.Now().UTC().Truncate(24 * time.Hour),
	}

	if ar.HeaderFromDomain != "example.com" {
		t.Errorf("Expected HeaderFromDomain 'example.com', got '%s'", ar.HeaderFromDomain)
	}
	if ar.SourceIP.String() != "192.168.1.1" {
		t.Errorf("Expected SourceIP '192.168.1.1', got '%s'", ar.SourceIP.String())
	}
	if !ar.SPFAligned {
		t.Error("Expected SPFAligned to be true")
	}
	if len(ar.DKIMResults) != 1 {
		t.Errorf("Expected 1 DKIM result, got %d", len(ar.DKIMResults))
	}
}

func TestReportFilter(t *testing.T) {
	filter := ReportFilter{
		Domain:   "example.com",
		OrgName:  "Google",
		DateFrom: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateTo:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		Status:   "pending",
	}

	if filter.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got '%s'", filter.Domain)
	}
	if filter.Status != "pending" {
		t.Errorf("Expected Status 'pending', got '%s'", filter.Status)
	}
}

func TestReportStatus(t *testing.T) {
	tests := []struct {
		status   ReportStatus
		expected string
	}{
		{ReportStatusPending, "pending"},
		{ReportStatusSent, "sent"},
		{ReportStatusFailed, "failed"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("Expected status '%s', got '%s'", tt.expected, string(tt.status))
		}
	}
}

func TestDomainStats(t *testing.T) {
	stats := &DomainStats{
		Domain:           "example.com",
		PeriodStart:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:        time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC),
		TotalMessages:    1000,
		PassCount:        900,
		FailCount:        100,
		PassRate:         90.0,
		DKIMAlignedCount: 850,
		SPFAlignedCount:  880,
		BySource: []SourceStats{
			{SourceIP: "192.168.1.1", Count: 500, PassCount: 450, FailCount: 50},
		},
		ReportsReceived: 5,
		ReportingOrgs:   []string{"Google", "Microsoft"},
	}

	if stats.PassRate != 90.0 {
		t.Errorf("Expected PassRate 90.0, got %f", stats.PassRate)
	}
	if stats.TotalMessages != 1000 {
		t.Errorf("Expected TotalMessages 1000, got %d", stats.TotalMessages)
	}
	if len(stats.BySource) != 1 {
		t.Errorf("Expected 1 source stat, got %d", len(stats.BySource))
	}
}

func TestReceivedReport(t *testing.T) {
	report := &ReceivedReport{
		OrgName:         "Test Org",
		Email:           "dmarc@test.org",
		ReportID:        "test-123",
		Domain:          "example.com",
		DateBegin:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateEnd:         time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		Policy:          "reject",
		ADKIM:           "r",
		ASPF:            "r",
		SubdomainPolicy: "quarantine",
		Percentage:      100,
		RecordCount:     10,
		PassCount:       8,
		FailCount:       2,
	}

	if report.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got '%s'", report.Domain)
	}
	if report.RecordCount != 10 {
		t.Errorf("Expected RecordCount 10, got %d", report.RecordCount)
	}
}

func TestSentReport(t *testing.T) {
	report := &SentReport{
		Domain:       "example.com",
		RUAAddresses: []string{"mailto:dmarc@example.com"},
		DateBegin:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DateEnd:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		ReportID:     "sent-123",
		RecordCount:  5,
		Status:       string(ReportStatusPending),
	}

	if len(report.RUAAddresses) != 1 {
		t.Errorf("Expected 1 RUA address, got %d", len(report.RUAAddresses))
	}
	if report.Status != "pending" {
		t.Errorf("Expected Status 'pending', got '%s'", report.Status)
	}
}

func TestReportRecord(t *testing.T) {
	record := ReportRecord{
		SourceIP:     net.ParseIP("10.0.0.1"),
		Count:        100,
		Disposition:  "none",
		DKIMResult:   "pass",
		SPFResult:    "pass",
		HeaderFrom:   "example.com",
		EnvelopeFrom: "bounce@example.com",
		EnvelopeTo:   "recipient@other.com",
	}

	if record.Count != 100 {
		t.Errorf("Expected Count 100, got %d", record.Count)
	}
	if record.Disposition != "none" {
		t.Errorf("Expected Disposition 'none', got '%s'", record.Disposition)
	}
}

func TestCollectorConfig(t *testing.T) {
	config := CollectorConfig{
		Enabled:   true,
		BatchSize: 100,
	}

	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if config.BatchSize != 100 {
		t.Errorf("Expected BatchSize 100, got %d", config.BatchSize)
	}
}

func TestWorkerConfig(t *testing.T) {
	config := WorkerConfig{
		Enabled:    true,
		ReportTime: "02:00",
		MaxRetries: 5,
		RetryIntervals: []time.Duration{
			5 * time.Minute,
			15 * time.Minute,
		},
	}

	if config.ReportTime != "02:00" {
		t.Errorf("Expected ReportTime '02:00', got '%s'", config.ReportTime)
	}
	if config.MaxRetries != 5 {
		t.Errorf("Expected MaxRetries 5, got %d", config.MaxRetries)
	}
}

func TestDateRangeMethods(t *testing.T) {
	dr := DateRange{
		Begin: 1700000000,
		End:   1700086400,
	}

	beginTime := dr.BeginTime()
	endTime := dr.EndTime()

	if beginTime.Unix() != 1700000000 {
		t.Errorf("Expected BeginTime Unix 1700000000, got %d", beginTime.Unix())
	}
	if endTime.Unix() != 1700086400 {
		t.Errorf("Expected EndTime Unix 1700086400, got %d", endTime.Unix())
	}
}

// Benchmark XML parsing
func BenchmarkXMLParsing(b *testing.B) {
	xmlData := `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Test</org_name>
    <email>test@test.com</email>
    <report_id>123</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>test.com</domain>
    <p>none</p>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>test.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>test.com</domain><result>pass</result></dkim>
      <spf><domain>test.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`

	data := []byte(xmlData)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var report AggregateReport
		xml.Unmarshal(data, &report)
	}
}

// Test context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Verify context is cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled")
	}
}

func TestSourceStats(t *testing.T) {
	stats := SourceStats{
		SourceIP:  "10.0.0.1",
		Count:     500,
		PassCount: 450,
		FailCount: 50,
	}

	if stats.Count != 500 {
		t.Errorf("Expected Count 500, got %d", stats.Count)
	}
	if stats.PassCount+stats.FailCount != stats.Count {
		t.Error("PassCount + FailCount should equal Count")
	}
}

func TestDKIMResultJSON(t *testing.T) {
	result := DKIMResultJSON{
		Domain:   "example.com",
		Selector: "s1",
		Result:   "pass",
		Aligned:  true,
	}

	if result.Domain != "example.com" {
		t.Errorf("Expected Domain 'example.com', got '%s'", result.Domain)
	}
	if !result.Aligned {
		t.Error("Expected Aligned to be true")
	}
}
