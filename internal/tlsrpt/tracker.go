package tlsrpt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/mtasts"
)

// Tracker records TLS connection results for TLS-RPT reporting.
type Tracker struct {
	store   *Store
	logger  *slog.Logger
	enabled bool

	// Buffer for batching inserts
	mu      sync.Mutex
	buffer  []*ConnectionResult
	bufSize int
}

// TrackerConfig contains configuration for the tracker.
type TrackerConfig struct {
	Enabled   bool
	BatchSize int
}

// NewTracker creates a new TLS connection tracker.
func NewTracker(store *Store, logger *slog.Logger, configs ...TrackerConfig) *Tracker {
	var config TrackerConfig
	if len(configs) > 0 {
		config = configs[0]
	} else {
		config = TrackerConfig{Enabled: true, BatchSize: 50}
	}

	bufSize := config.BatchSize
	if bufSize <= 0 {
		bufSize = 50
	}

	return &Tracker{
		store:   store,
		logger:  logger.With("component", "tlsrpt.tracker"),
		enabled: config.Enabled,
		buffer:  make([]*ConnectionResult, 0, bufSize),
		bufSize: bufSize,
	}
}

// RecordSuccess records a successful TLS connection.
// Accepts tls.ConnectionState (value or pointer) and policy as interface{}.
func (t *Tracker) RecordSuccess(ctx context.Context, domain, mxHost string, connState tls.ConnectionState, policyIface interface{}) {
	if !t.enabled {
		return
	}

	result := &ConnectionResult{
		ID:              uuid.New(),
		RecipientDomain: domain,
		MXHost:          mxHost,
		ResultType:      ResultTypeSuccess,
		Success:         true,
		CreatedAt:       time.Now(),
	}

	// Set policy information
	if policy, ok := policyIface.(*mtasts.CachedPolicy); ok && policy != nil {
		result.PolicyType = PolicyTypeSTS
		result.PolicyDomain = policy.Domain
		result.PolicyString = policy.MXPatterns
	} else {
		result.PolicyType = PolicyTypeNoPolicyFound
	}

	// Extract TLS details
	result.TLSVersion = tlsVersionString(connState.Version)
	result.CipherSuite = tls.CipherSuiteName(connState.CipherSuite)

	if len(connState.PeerCertificates) > 0 {
		cert := connState.PeerCertificates[0]
		result.CertIssuer = cert.Issuer.String()
		result.CertSubject = cert.Subject.String()
		result.CertExpiry = cert.NotAfter
	}

	t.record(ctx, result)
}

// RecordFailure records a TLS connection failure.
// Accepts policy as interface{}.
func (t *Tracker) RecordFailure(ctx context.Context, domain, mxHost string, err error, policyIface interface{}) {
	if !t.enabled {
		return
	}

	result := &ConnectionResult{
		ID:              uuid.New(),
		RecipientDomain: domain,
		MXHost:          mxHost,
		Success:         false,
		CreatedAt:       time.Now(),
	}

	// Classify the error
	result.ResultType = classifyTLSError(err)
	if err != nil {
		result.FailureReasonText = err.Error()
	}

	// Set policy information
	if policy, ok := policyIface.(*mtasts.CachedPolicy); ok && policy != nil {
		result.PolicyType = PolicyTypeSTS
		result.PolicyDomain = policy.Domain
		result.PolicyString = policy.MXPatterns
	} else {
		result.PolicyType = PolicyTypeNoPolicyFound
	}

	t.record(ctx, result)
}

// RecordWithDetails records a connection result with full details.
func (t *Tracker) RecordWithDetails(ctx context.Context, result *ConnectionResult) {
	if !t.enabled {
		return
	}

	if result.ID == uuid.Nil {
		result.ID = uuid.New()
	}
	if result.CreatedAt.IsZero() {
		result.CreatedAt = time.Now()
	}

	t.record(ctx, result)
}

// record adds a result to the buffer and flushes if needed.
func (t *Tracker) record(ctx context.Context, result *ConnectionResult) {
	t.mu.Lock()
	t.buffer = append(t.buffer, result)
	shouldFlush := len(t.buffer) >= t.bufSize
	t.mu.Unlock()

	if shouldFlush {
		t.Flush(ctx)
	}
}

// Flush writes buffered results to the database.
func (t *Tracker) Flush(ctx context.Context) error {
	t.mu.Lock()
	if len(t.buffer) == 0 {
		t.mu.Unlock()
		return nil
	}
	toFlush := t.buffer
	t.buffer = make([]*ConnectionResult, 0, t.bufSize)
	t.mu.Unlock()

	for _, result := range toFlush {
		if err := t.store.SaveConnectionResult(ctx, result); err != nil {
			t.logger.Error("failed to save connection result",
				"domain", result.RecipientDomain,
				"mx", result.MXHost,
				"error", err,
			)
		}
	}

	t.logger.Debug("flushed TLS connection results", "count", len(toFlush))
	return nil
}

// Enabled returns whether the tracker is enabled.
func (t *Tracker) Enabled() bool {
	return t.enabled
}

// SetEnabled enables or disables the tracker.
func (t *Tracker) SetEnabled(enabled bool) {
	t.enabled = enabled
}

// Close flushes any remaining results.
func (t *Tracker) Close(ctx context.Context) error {
	return t.Flush(ctx)
}

// classifyTLSError maps TLS errors to RFC 8460 result types.
func classifyTLSError(err error) string {
	if err == nil {
		return ResultTypeSuccess
	}

	errStr := strings.ToLower(err.Error())

	// Check for specific certificate errors
	if certErr, ok := err.(*tls.CertificateVerificationError); ok {
		return classifyCertError(certErr.Err)
	}

	// Check error message patterns
	switch {
	case strings.Contains(errStr, "certificate has expired"):
		return ResultTypeCertificateExpired
	case strings.Contains(errStr, "certificate is not trusted"):
		return ResultTypeCertificateNotTrusted
	case strings.Contains(errStr, "certificate name") ||
		strings.Contains(errStr, "doesn't match") ||
		strings.Contains(errStr, "hostname mismatch"):
		return ResultTypeCertificateHostMismatch
	case strings.Contains(errStr, "starttls") ||
		strings.Contains(errStr, "tls not supported"):
		return ResultTypeSTARTTLSNotSupported
	case strings.Contains(errStr, "sts") && strings.Contains(errStr, "policy"):
		if strings.Contains(errStr, "fetch") {
			return ResultTypeSTSPolicyFetchError
		}
		return ResultTypeSTSPolicyInvalid
	case strings.Contains(errStr, "certificate verify") ||
		strings.Contains(errStr, "x509"):
		return ResultTypeValidationFailure
	case strings.Contains(errStr, "tlsa"):
		return ResultTypeTLSAInvalid
	case strings.Contains(errStr, "dnssec"):
		return ResultTypeDNSSECInvalid
	default:
		return ResultTypeValidationFailure
	}
}

// classifyCertError classifies x509 certificate errors.
func classifyCertError(err error) string {
	if err == nil {
		return ResultTypeSuccess
	}

	switch e := err.(type) {
	case x509.CertificateInvalidError:
		switch e.Reason {
		case x509.Expired:
			return ResultTypeCertificateExpired
		case x509.NotAuthorizedToSign, x509.IncompatibleUsage:
			return ResultTypeCertificateNotTrusted
		default:
			return ResultTypeValidationFailure
		}
	case x509.HostnameError:
		return ResultTypeCertificateHostMismatch
	case x509.UnknownAuthorityError:
		return ResultTypeCertificateNotTrusted
	default:
		return ResultTypeValidationFailure
	}
}

// tlsVersionString converts a TLS version to a string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

// ResolveLocalIP returns the local IP used for outbound connections.
func ResolveLocalIP() net.IP {
	// Try to determine outbound IP by making a UDP "connection"
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}
