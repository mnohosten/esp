// Package tlsrpt implements TLS-RPT (RFC 8460) report handling.
package tlsrpt

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// Report represents a TLS-RPT report per RFC 8460.
type Report struct {
	OrganizationName string       `json:"organization-name"`
	DateRange        DateRange    `json:"date-range"`
	ContactInfo      string       `json:"contact-info,omitempty"`
	ReportID         string       `json:"report-id"`
	Policies         []PolicyResult `json:"policies"`
}

// DateRange specifies the time period covered by the report.
type DateRange struct {
	StartDateTime time.Time `json:"start-datetime"`
	EndDateTime   time.Time `json:"end-datetime"`
}

// PolicyResult represents the results for a single policy.
type PolicyResult struct {
	Policy         Policy          `json:"policy"`
	Summary        Summary         `json:"summary"`
	FailureDetails []FailureDetail `json:"failure-details,omitempty"`
}

// Policy describes the TLS policy that was applied.
type Policy struct {
	PolicyType   string   `json:"policy-type"`   // "sts", "tlsa", "no-policy-found"
	PolicyString []string `json:"policy-string,omitempty"`
	PolicyDomain string   `json:"policy-domain"`
	MXHost       []string `json:"mx-host,omitempty"`
}

// PolicyType constants
const (
	PolicyTypeSTS           = "sts"
	PolicyTypeTLSA          = "tlsa"
	PolicyTypeNoPolicyFound = "no-policy-found"
)

// Summary contains counts of successful and failed sessions.
type Summary struct {
	TotalSuccessfulSessionCount int `json:"total-successful-session-count"`
	TotalFailureSessionCount    int `json:"total-failure-session-count"`
}

// FailureDetail describes a specific failure type.
type FailureDetail struct {
	ResultType            string `json:"result-type"`
	SendingMTAIP          string `json:"sending-mta-ip,omitempty"`
	ReceivingIP           string `json:"receiving-ip,omitempty"`
	ReceivingMXHostname   string `json:"receiving-mx-hostname,omitempty"`
	ReceivingMXHelo       string `json:"receiving-mx-helo,omitempty"`
	FailedSessionCount    int    `json:"failed-session-count"`
	AdditionalInformation string `json:"additional-information,omitempty"`
	FailureReasonCode     string `json:"failure-reason-code,omitempty"`
}

// Result types as defined in RFC 8460
const (
	ResultTypeSuccess               = "success"
	ResultTypeSTARTTLSNotSupported  = "starttls-not-supported"
	ResultTypeCertificateHostMismatch = "certificate-host-mismatch"
	ResultTypeCertificateExpired    = "certificate-expired"
	ResultTypeCertificateNotTrusted = "certificate-not-trusted"
	ResultTypeValidationFailure     = "validation-failure"
	ResultTypeTLSAInvalid           = "tlsa-invalid"
	ResultTypeDNSSECInvalid         = "dnssec-invalid"
	ResultTypeSTSPolicyFetchError   = "sts-policy-fetch-error"
	ResultTypeSTSPolicyInvalid      = "sts-policy-invalid"
	ResultTypeSTSWebPKIInvalid      = "sts-webpki-invalid"
)

// ConnectionResult records the outcome of a TLS connection attempt.
type ConnectionResult struct {
	ID              uuid.UUID  `json:"id"`
	QueueID         *uuid.UUID `json:"queue_id,omitempty"`
	RecipientDomain string     `json:"recipient_domain"`
	MXHost          string     `json:"mx_host"`
	MXIP            net.IP     `json:"mx_ip,omitempty"`

	// Result
	ResultType string `json:"result_type"`
	Success    bool   `json:"success"`

	// Policy information
	PolicyType   string   `json:"policy_type"`
	PolicyDomain string   `json:"policy_domain,omitempty"`
	PolicyString []string `json:"policy_string,omitempty"`

	// Failure details
	FailureReasonCode string `json:"failure_reason_code,omitempty"`
	FailureReasonText string `json:"failure_reason_text,omitempty"`
	SendingMTAIP      net.IP `json:"sending_mta_ip,omitempty"`
	ReceivingIP       net.IP `json:"receiving_ip,omitempty"`
	ReceivingMXHostname string `json:"receiving_mx_hostname,omitempty"`
	ReceivingMXHelo   string `json:"receiving_mx_helo,omitempty"`

	// TLS details
	TLSVersion  string    `json:"tls_version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	CertIssuer  string    `json:"cert_issuer,omitempty"`
	CertSubject string    `json:"cert_subject,omitempty"`
	CertExpiry  time.Time `json:"cert_expiry,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// ReceivedReport represents a stored received TLS-RPT report.
type ReceivedReport struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationName string     `json:"organization_name"`
	ReportID         string     `json:"report_id"`
	ContactInfo      string     `json:"contact_info,omitempty"`
	DateRangeStart   time.Time  `json:"date_range_start"`
	DateRangeEnd     time.Time  `json:"date_range_end"`
	PolicyDomain     string     `json:"policy_domain"`
	RawReport        *Report    `json:"raw_report,omitempty"`
	TotalSuccessful  int        `json:"total_successful"`
	TotalFailed      int        `json:"total_failed"`
	ReceivedAt       time.Time  `json:"received_at"`
	ProcessedAt      *time.Time `json:"processed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// SentReport represents an outbound TLS-RPT report.
type SentReport struct {
	ID             uuid.UUID  `json:"id"`
	ReportID       string     `json:"report_id"`
	DateRangeStart time.Time  `json:"date_range_start"`
	DateRangeEnd   time.Time  `json:"date_range_end"`
	PolicyDomain   string     `json:"policy_domain"`
	RUAURI         string     `json:"rua_uri"`
	Policies       []PolicyResult `json:"policies,omitempty"`
	ReportJSON     *Report    `json:"-"`
	Status         string     `json:"status"`
	SentAt         *time.Time `json:"sent_at,omitempty"`
	Error          string     `json:"error,omitempty"`
	RetryCount     int        `json:"retry_count"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ReportStatus constants
const (
	ReportStatusPending = "pending"
	ReportStatusSent    = "sent"
	ReportStatusFailed  = "failed"
)

// DailyAggregate contains aggregated TLS results for a domain/day.
type DailyAggregate struct {
	ID              uuid.UUID         `json:"id"`
	ReportDate      time.Time         `json:"report_date"`
	RecipientDomain string            `json:"recipient_domain"`
	PolicyType      string            `json:"policy_type"`
	PolicyDomain    string            `json:"policy_domain,omitempty"`
	TotalSuccessful int               `json:"total_successful"`
	TotalFailed     int               `json:"total_failed"`
	FailureDetails  map[string]int    `json:"failure_details"` // result_type -> count
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// TLSStats contains TLS connection statistics.
type TLSStats struct {
	Period           string         `json:"period"`
	TotalConnections int            `json:"total_connections"`
	Successful       int            `json:"successful"`
	Failed           int            `json:"failed"`
	SuccessRate      float64        `json:"success_rate"`
	ByResultType     map[string]int `json:"by_result_type"`
	ByPolicyType     map[string]int `json:"by_policy_type"`
	TopFailingDomains []DomainStats `json:"top_failing_domains,omitempty"`
}

// DomainStats contains per-domain TLS statistics.
type DomainStats struct {
	Domain     string  `json:"domain"`
	Total      int     `json:"total"`
	Successful int     `json:"successful"`
	Failed     int     `json:"failed"`
	FailRate   float64 `json:"fail_rate"`
}

// ReportFilter contains filter options for querying reports.
type ReportFilter struct {
	Domain   string
	DateFrom time.Time
	DateTo   time.Time
	Status   string
}

// DNSRecord represents a TLS-RPT DNS TXT record.
type DNSRecord struct {
	Version string   `json:"version"` // "TLSRPTv1"
	RUA     []string `json:"rua"`     // Reporting URIs
}
