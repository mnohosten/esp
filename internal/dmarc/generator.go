package dmarc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Generator creates DMARC aggregate reports for outbound sending.
type Generator struct {
	store     *Store
	hostname  string
	orgName   string
	email     string
	logger    *slog.Logger
}

// GeneratorConfig contains configuration for the report generator.
type GeneratorConfig struct {
	Hostname string
	OrgName  string
	Email    string
}

// NewGenerator creates a new DMARC report generator.
func NewGenerator(store *Store, logger *slog.Logger, config GeneratorConfig) *Generator {
	return &Generator{
		store:    store,
		hostname: config.Hostname,
		orgName:  config.OrgName,
		email:    config.Email,
		logger:   logger.With("component", "dmarc.generator"),
	}
}

// GenerateReport creates an aggregate report for a domain.
func (g *Generator) GenerateReport(ctx context.Context, domain string, start, end time.Time) (*AggregateReport, error) {
	// Get auth results for this domain and date range
	reportDate := start.UTC().Truncate(24 * time.Hour)
	results, err := g.store.GetAuthResultsForDomain(ctx, domain, reportDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth results: %w", err)
	}

	if len(results) == 0 {
		return nil, nil
	}

	// Aggregate results by source IP
	aggregated := g.aggregateResults(results)

	// Generate report ID
	reportID := fmt.Sprintf("%s!%s!%d!%d",
		g.hostname, domain, start.Unix(), end.Unix())

	report := &AggregateReport{
		ReportMetadata: ReportMetadata{
			OrgName:  g.orgName,
			Email:    g.email,
			ReportID: reportID,
			DateRange: DateRange{
				Begin: start.Unix(),
				End:   end.Unix(),
			},
		},
		PolicyPublished: PolicyPublished{
			Domain: domain,
			ADKIM:  "r", // Default to relaxed
			ASPF:   "r",
			Policy: g.getMostCommonPolicy(results),
		},
		Records: aggregated,
	}

	return report, nil
}

// aggregateResults groups results by source IP and header_from.
func (g *Generator) aggregateResults(results []AuthResult) []Record {
	type key struct {
		sourceIP   string
		headerFrom string
		spfResult  string
		dkimResult string
	}

	aggregates := make(map[key]*Record)

	for _, r := range results {
		sourceIP := r.SourceIP.String()
		dkimResult := g.getDKIMOverallResult(r.DKIMResults)
		spfResult := r.SPFResult

		k := key{
			sourceIP:   sourceIP,
			headerFrom: r.HeaderFromDomain,
			spfResult:  spfResult,
			dkimResult: dkimResult,
		}

		if existing, ok := aggregates[k]; ok {
			existing.Row.Count++
		} else {
			// Determine disposition based on DMARC result
			disposition := "none"
			if r.Disposition != "" {
				disposition = r.Disposition
			} else if r.DMARCResult == "fail" && r.DMARCPolicy != "" && r.DMARCPolicy != "none" {
				disposition = r.DMARCPolicy
			}

			// Convert SPF result to pass/fail for DMARC
			spfPolicyResult := "fail"
			if spfResult == "pass" {
				spfPolicyResult = "pass"
			}

			// Convert DKIM result to pass/fail for DMARC
			dkimPolicyResult := "fail"
			if dkimResult == "pass" {
				dkimPolicyResult = "pass"
			}

			record := &Record{
				Row: Row{
					SourceIP: sourceIP,
					Count:    1,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: disposition,
						DKIM:        dkimPolicyResult,
						SPF:         spfPolicyResult,
					},
				},
				Identifiers: Identifiers{
					HeaderFrom:   r.HeaderFromDomain,
					EnvelopeFrom: r.EnvelopeFromDomain,
				},
				AuthResults: AuthResults{},
			}

			// Add SPF auth result
			if r.SPFDomain != "" {
				record.AuthResults.SPF = []SPFAuthResult{
					{
						Domain: r.SPFDomain,
						Scope:  "mfrom",
						Result: spfResult,
					},
				}
			}

			// Add DKIM auth results
			for _, dkimRes := range r.DKIMResults {
				record.AuthResults.DKIM = append(record.AuthResults.DKIM, DKIMAuthResult{
					Domain:   dkimRes.Domain,
					Selector: dkimRes.Selector,
					Result:   dkimRes.Result,
				})
			}

			aggregates[k] = record
		}
	}

	// Convert map to slice
	records := make([]Record, 0, len(aggregates))
	for _, rec := range aggregates {
		records = append(records, *rec)
	}

	return records
}

// getDKIMOverallResult determines the overall DKIM result from multiple signatures.
func (g *Generator) getDKIMOverallResult(dkimResults []DKIMResultJSON) string {
	for _, r := range dkimResults {
		if r.Result == "pass" {
			return "pass"
		}
	}
	if len(dkimResults) == 0 {
		return "none"
	}
	return "fail"
}

// getMostCommonPolicy gets the most commonly seen policy from results.
func (g *Generator) getMostCommonPolicy(results []AuthResult) string {
	counts := make(map[string]int)
	for _, r := range results {
		if r.DMARCPolicy != "" {
			counts[r.DMARCPolicy]++
		}
	}

	maxCount := 0
	policy := "none"
	for p, c := range counts {
		if c > maxCount {
			maxCount = c
			policy = p
		}
	}
	return policy
}

// ToXML serializes a report to XML format.
func (g *Generator) ToXML(report *AggregateReport) ([]byte, error) {
	output, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML header
	xmlHeader := []byte(xml.Header)
	return append(xmlHeader, output...), nil
}

// CompressReport gzip-compresses the XML report.
func (g *Generator) CompressReport(xmlData []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	if _, err := gw.Write(xmlData); err != nil {
		return nil, fmt.Errorf("failed to write gzip: %w", err)
	}

	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip: %w", err)
	}

	return buf.Bytes(), nil
}

// GenerateFilename creates a filename for the report.
func (g *Generator) GenerateFilename(report *AggregateReport) string {
	// Format: receiver!policy-domain!begin-timestamp!end-timestamp.xml.gz
	return fmt.Sprintf("%s!%s!%d!%d.xml.gz",
		strings.ReplaceAll(g.hostname, ".", "_"),
		strings.ReplaceAll(report.PolicyPublished.Domain, ".", "_"),
		report.ReportMetadata.DateRange.Begin,
		report.ReportMetadata.DateRange.End,
	)
}

// LookupRUAAddresses looks up the DMARC RUA addresses for a domain.
func (g *Generator) LookupRUAAddresses(ctx context.Context, domain string) ([]string, error) {
	// Look up _dmarc.domain TXT record
	dmarcDomain := "_dmarc." + domain

	records, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup DMARC record: %w", err)
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			return g.parseRUA(record), nil
		}
	}

	return nil, fmt.Errorf("no DMARC record found for %s", domain)
}

// parseRUA extracts RUA addresses from a DMARC record.
func (g *Generator) parseRUA(record string) []string {
	var addresses []string

	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "rua=") {
			ruaValue := strings.TrimPrefix(part, "rua=")
			ruaValue = strings.TrimPrefix(ruaValue, "RUA=")

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

// ValidateExternalRUA validates that an external RUA address accepts reports for a domain.
// Per RFC 7489 section 7.1, external domains must have a special record.
func (g *Generator) ValidateExternalRUA(ctx context.Context, reportDomain, ruaAddress string) (bool, error) {
	// Extract domain from RUA address
	ruaAddress = strings.TrimPrefix(ruaAddress, "mailto:")
	parts := strings.Split(ruaAddress, "@")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid RUA address format")
	}
	ruaDomain := parts[1]

	// If same domain, no external validation needed
	if strings.EqualFold(ruaDomain, reportDomain) {
		return true, nil
	}

	// Look up: reportDomain._report._dmarc.ruaDomain
	verifyDomain := fmt.Sprintf("%s._report._dmarc.%s", reportDomain, ruaDomain)

	records, err := net.DefaultResolver.LookupTXT(ctx, verifyDomain)
	if err != nil {
		// Record not found means external authorization not granted
		return false, nil
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			return true, nil
		}
	}

	return false, nil
}
