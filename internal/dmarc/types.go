// Package dmarc implements DMARC aggregate report handling per RFC 7489.
package dmarc

import (
	"encoding/xml"
	"net"
	"time"

	"github.com/google/uuid"
)

// AggregateReport represents a DMARC aggregate report (RFC 7489 Appendix C).
type AggregateReport struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version,omitempty"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []Record        `xml:"record"`
}

// ReportMetadata contains information about the reporting organization.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
	Errors           []string  `xml:"error,omitempty"`
}

// DateRange specifies the time period covered by the report.
type DateRange struct {
	Begin int64 `xml:"begin"` // Unix timestamp
	End   int64 `xml:"end"`   // Unix timestamp
}

// BeginTime returns the begin date as a time.Time.
func (d DateRange) BeginTime() time.Time {
	return time.Unix(d.Begin, 0).UTC()
}

// EndTime returns the end date as a time.Time.
func (d DateRange) EndTime() time.Time {
	return time.Unix(d.End, 0).UTC()
}

// PolicyPublished contains the DMARC policy for the domain.
type PolicyPublished struct {
	Domain          string `xml:"domain"`
	ADKIM           string `xml:"adkim,omitempty"`  // r=relaxed, s=strict
	ASPF            string `xml:"aspf,omitempty"`   // r=relaxed, s=strict
	Policy          string `xml:"p"`                // none, quarantine, reject
	SubdomainPolicy string `xml:"sp,omitempty"`     // none, quarantine, reject
	Percentage      int    `xml:"pct,omitempty"`    // 0-100
	FailureOptions  string `xml:"fo,omitempty"`     // Failure reporting options
	ReportFormat    string `xml:"rf,omitempty"`     // Report format
	ReportInterval  int    `xml:"ri,omitempty"`     // Reporting interval in seconds
	ReportURI       string `xml:"rua,omitempty"`    // Aggregate report URI
	ForensicURI     string `xml:"ruf,omitempty"`    // Forensic report URI
}

// Record represents a single authentication result record.
type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row contains the source IP and policy evaluation results.
type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

// PolicyEvaluated contains the results of policy evaluation.
type PolicyEvaluated struct {
	Disposition string        `xml:"disposition"`          // none, quarantine, reject
	DKIM        string        `xml:"dkim"`                 // pass, fail
	SPF         string        `xml:"spf"`                  // pass, fail
	Reason      []PolicyReason `xml:"reason,omitempty"`
}

// PolicyReason provides additional context for policy decisions.
type PolicyReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment,omitempty"`
}

// Identifiers contains the relevant identifiers from the message.
type Identifiers struct {
	EnvelopeTo   string `xml:"envelope_to,omitempty"`
	EnvelopeFrom string `xml:"envelope_from,omitempty"`
	HeaderFrom   string `xml:"header_from"`
}

// AuthResults contains the authentication results for SPF and DKIM.
type AuthResults struct {
	DKIM []DKIMAuthResult `xml:"dkim,omitempty"`
	SPF  []SPFAuthResult  `xml:"spf,omitempty"`
}

// DKIMAuthResult represents a single DKIM authentication result.
type DKIMAuthResult struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector,omitempty"`
	Result      string `xml:"result"` // none, pass, fail, policy, neutral, temperror, permerror
	HumanResult string `xml:"human_result,omitempty"`
}

// SPFAuthResult represents a single SPF authentication result.
type SPFAuthResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope,omitempty"` // mfrom, helo
	Result string `xml:"result"`          // none, neutral, pass, fail, softfail, temperror, permerror
}

// ReceivedReport represents a stored received DMARC report.
type ReceivedReport struct {
	ID               uuid.UUID  `json:"id"`
	OrgName          string     `json:"org_name"`
	Email            string     `json:"email,omitempty"`
	ExtraContactInfo string     `json:"extra_contact_info,omitempty"`
	ReportID         string     `json:"report_id"`
	DateBegin        time.Time  `json:"date_begin"`
	DateEnd          time.Time  `json:"date_end"`
	Domain           string     `json:"domain"`
	ADKIM            string     `json:"adkim,omitempty"`
	ASPF             string     `json:"aspf,omitempty"`
	Policy           string     `json:"policy"`
	SubdomainPolicy  string     `json:"subdomain_policy,omitempty"`
	Percentage       int        `json:"pct,omitempty"`
	RawXML           string     `json:"-"`
	ReceivedAt       time.Time  `json:"received_at"`
	SourceIP         net.IP     `json:"source_ip,omitempty"`
	SourceEmail      string     `json:"source_email,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	RecordCount      int        `json:"record_count,omitempty"`
	PassCount        int        `json:"pass_count,omitempty"`
	FailCount        int        `json:"fail_count,omitempty"`
}

// ReportRecord represents a stored record from a received report.
type ReportRecord struct {
	ID           uuid.UUID         `json:"id"`
	ReportID     uuid.UUID         `json:"report_id"`
	SourceIP     net.IP            `json:"source_ip"`
	Count        int               `json:"count"`
	Disposition  string            `json:"disposition"`
	DKIMResult   string            `json:"dkim_result"`
	SPFResult    string            `json:"spf_result"`
	EnvelopeTo   string            `json:"envelope_to,omitempty"`
	EnvelopeFrom string            `json:"envelope_from,omitempty"`
	HeaderFrom   string            `json:"header_from"`
	AuthResults  *AuthResultsJSON  `json:"auth_results,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// AuthResultsJSON is the JSONB structure for auth results.
type AuthResultsJSON struct {
	DKIM []DKIMAuthResult `json:"dkim,omitempty"`
	SPF  []SPFAuthResult  `json:"spf,omitempty"`
}

// AuthResult represents authentication data we collect for outbound reports.
type AuthResult struct {
	ID                 uuid.UUID        `json:"id"`
	MessageID          string           `json:"message_id,omitempty"`
	HeaderFromDomain   string           `json:"header_from_domain"`
	EnvelopeFromDomain string           `json:"envelope_from_domain,omitempty"`
	EnvelopeToDomain   string           `json:"envelope_to_domain,omitempty"`
	SourceIP           net.IP           `json:"source_ip"`
	SPFResult          string           `json:"spf_result"`
	SPFDomain          string           `json:"spf_domain,omitempty"`
	SPFAligned         bool             `json:"spf_aligned"`
	DKIMResults        []DKIMResultJSON `json:"dkim_results,omitempty"`
	DKIMAligned        bool             `json:"dkim_aligned"`
	DMARCResult        string           `json:"dmarc_result"`
	DMARCPolicy        string           `json:"dmarc_policy,omitempty"`
	Disposition        string           `json:"disposition,omitempty"`
	ReceivedAt         time.Time        `json:"received_at"`
	ReportDate         time.Time        `json:"report_date"`
}

// DKIMResultJSON represents DKIM result stored in JSONB.
type DKIMResultJSON struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector,omitempty"`
	Result   string `json:"result"`
	Aligned  bool   `json:"aligned"`
}

// SentReport represents an outbound DMARC report we've generated.
type SentReport struct {
	ID               uuid.UUID  `json:"id"`
	Domain           string     `json:"domain"`
	RUAAddresses     []string   `json:"rua_addresses"`
	DateBegin        time.Time  `json:"date_begin"`
	DateEnd          time.Time  `json:"date_end"`
	ReportID         string     `json:"report_id"`
	RecordCount      int        `json:"record_count"`
	ReportXML        string     `json:"-"`
	CompressedReport []byte     `json:"-"`
	Status           string     `json:"status"`
	LastError        string     `json:"last_error,omitempty"`
	Attempts         int        `json:"attempts"`
	CreatedAt        time.Time  `json:"created_at"`
	SentAt           *time.Time `json:"sent_at,omitempty"`
}

// ReportStatus represents the status of a sent report.
type ReportStatus string

const (
	ReportStatusPending ReportStatus = "pending"
	ReportStatusSent    ReportStatus = "sent"
	ReportStatusFailed  ReportStatus = "failed"
)

// ReportFilter contains filter options for querying reports.
type ReportFilter struct {
	Domain    string
	OrgName   string
	DateFrom  time.Time
	DateTo    time.Time
	Status    string
}

// DomainStats contains DMARC statistics for a domain.
type DomainStats struct {
	Domain           string                `json:"domain"`
	PeriodStart      time.Time             `json:"period_start"`
	PeriodEnd        time.Time             `json:"period_end"`
	TotalMessages    int                   `json:"total_messages"`
	PassCount        int                   `json:"pass_count"`
	FailCount        int                   `json:"fail_count"`
	PassRate         float64               `json:"pass_rate"`
	DKIMAlignedCount int                   `json:"dkim_aligned_count"`
	SPFAlignedCount  int                   `json:"spf_aligned_count"`
	BySource         []SourceStats         `json:"by_source,omitempty"`
	ReportsReceived  int                   `json:"reports_received"`
	ReportingOrgs    []string              `json:"reporting_orgs,omitempty"`
}

// SourceStats contains per-source-IP statistics.
type SourceStats struct {
	SourceIP  string `json:"source_ip"`
	Count     int    `json:"count"`
	PassCount int    `json:"pass_count"`
	FailCount int    `json:"fail_count"`
}
