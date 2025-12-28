package tlsrpt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Generator creates TLS-RPT reports for outbound sending.
type Generator struct {
	store       *Store
	hostname    string
	orgName     string
	contactInfo string
	logger      *slog.Logger
}

// GeneratorConfig contains configuration for the report generator.
type GeneratorConfig struct {
	Hostname    string
	OrgName     string
	ContactInfo string
}

// NewGenerator creates a new TLS-RPT report generator.
func NewGenerator(store *Store, logger *slog.Logger, config GeneratorConfig) *Generator {
	return &Generator{
		store:       store,
		hostname:    config.Hostname,
		orgName:     config.OrgName,
		contactInfo: config.ContactInfo,
		logger:      logger.With("component", "tlsrpt.generator"),
	}
}

// GenerateReport creates a TLS-RPT report for a domain.
func (g *Generator) GenerateReport(ctx context.Context, domain string, start, end time.Time) (*Report, error) {
	// Get results for this domain and date range
	results, err := g.store.GetResultsForDomain(ctx, domain, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}

	if len(results) == 0 {
		return nil, nil
	}

	// Aggregate results by policy
	policyResults := g.aggregateResults(results)

	// Generate report ID
	reportID := fmt.Sprintf("%s-%s-%d",
		g.hostname, domain, start.Unix())

	report := &Report{
		OrganizationName: g.orgName,
		DateRange: DateRange{
			StartDateTime: start,
			EndDateTime:   end,
		},
		ContactInfo: g.contactInfo,
		ReportID:    reportID,
		Policies:    policyResults,
	}

	return report, nil
}

// aggregateResults groups results by policy type and aggregates counts.
func (g *Generator) aggregateResults(results []ConnectionResult) []PolicyResult {
	// Group by policy type + domain
	type policyKey struct {
		policyType   string
		policyDomain string
	}

	aggregates := make(map[policyKey]*PolicyResult)

	for _, r := range results {
		key := policyKey{
			policyType:   r.PolicyType,
			policyDomain: r.PolicyDomain,
		}

		if existing, ok := aggregates[key]; ok {
			// Update existing
			if r.Success {
				existing.Summary.TotalSuccessfulSessionCount++
			} else {
				existing.Summary.TotalFailureSessionCount++
				g.addFailureDetail(existing, &r)
			}
		} else {
			// Create new policy result
			pr := &PolicyResult{
				Policy: Policy{
					PolicyType:   r.PolicyType,
					PolicyDomain: r.PolicyDomain,
					PolicyString: r.PolicyString,
				},
				Summary: Summary{},
			}

			if r.Success {
				pr.Summary.TotalSuccessfulSessionCount = 1
			} else {
				pr.Summary.TotalFailureSessionCount = 1
				g.addFailureDetail(pr, &r)
			}

			aggregates[key] = pr
		}
	}

	// Convert to slice
	results2 := make([]PolicyResult, 0, len(aggregates))
	for _, pr := range aggregates {
		results2 = append(results2, *pr)
	}

	return results2
}

// addFailureDetail adds or updates a failure detail entry.
func (g *Generator) addFailureDetail(pr *PolicyResult, r *ConnectionResult) {
	// Find existing failure detail with same result type
	for i := range pr.FailureDetails {
		if pr.FailureDetails[i].ResultType == r.ResultType {
			pr.FailureDetails[i].FailedSessionCount++
			return
		}
	}

	// Create new failure detail
	fd := FailureDetail{
		ResultType:         r.ResultType,
		FailedSessionCount: 1,
		ReceivingMXHostname: r.MXHost,
	}

	if r.SendingMTAIP != nil {
		fd.SendingMTAIP = r.SendingMTAIP.String()
	}
	if r.ReceivingIP != nil {
		fd.ReceivingIP = r.ReceivingIP.String()
	}
	if r.FailureReasonCode != "" {
		fd.FailureReasonCode = r.FailureReasonCode
	}
	if r.FailureReasonText != "" && len(r.FailureReasonText) < 200 {
		fd.AdditionalInformation = r.FailureReasonText
	}

	pr.FailureDetails = append(pr.FailureDetails, fd)
}

// ToJSON serializes a report to JSON.
func (g *Generator) ToJSON(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// LookupRUAAddresses looks up the TLS-RPT RUA addresses for a domain.
func (g *Generator) LookupRUAAddresses(ctx context.Context, domain string) ([]string, error) {
	// Look up _smtp._tls.domain TXT record
	tlsrptDomain := "_smtp._tls." + domain

	records, err := net.DefaultResolver.LookupTXT(ctx, tlsrptDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup TLS-RPT record: %w", err)
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=tlsrptv1") {
			return g.parseRUA(record), nil
		}
	}

	return nil, fmt.Errorf("no TLS-RPT record found for %s", domain)
}

// parseRUA extracts RUA addresses from a TLS-RPT record.
func (g *Generator) parseRUA(record string) []string {
	var addresses []string

	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "rua=") {
			ruaValue := part[4:] // Remove "rua="

			// Split by comma for multiple addresses
			for _, addr := range strings.Split(ruaValue, ",") {
				addr = strings.TrimSpace(addr)
				if addr != "" {
					addresses = append(addresses, addr)
				}
			}
		}
	}

	return addresses
}

// PrepareForSending creates a SentReport ready for delivery.
func (g *Generator) PrepareForSending(report *Report, ruaURI string) (*SentReport, error) {
	var policyDomain string
	if len(report.Policies) > 0 {
		policyDomain = report.Policies[0].Policy.PolicyDomain
	}

	return &SentReport{
		ID:             uuid.New(),
		ReportID:       report.ReportID,
		DateRangeStart: report.DateRange.StartDateTime,
		DateRangeEnd:   report.DateRange.EndDateTime,
		PolicyDomain:   policyDomain,
		RUAURI:         ruaURI,
		Policies:       report.Policies,
		ReportJSON:     report,
		Status:         ReportStatusPending,
		CreatedAt:      time.Now(),
	}, nil
}
