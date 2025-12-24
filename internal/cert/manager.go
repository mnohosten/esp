package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/mnohosten/esp/internal/event"
)

// ACME directory URLs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLProduction     = "https://acme.zerossl.com/v2/DV90"
)

// Config holds certificate manager configuration.
type Config struct {
	// ACME settings
	ACMEEmail     string        `mapstructure:"acme_email"`
	ACMEDirectory string        `mapstructure:"acme_directory"`
	ACMECacheDir  string        `mapstructure:"acme_cache_dir"`
	UseStaging    bool          `mapstructure:"use_staging"`

	// ZeroSSL EAB credentials
	ZeroSSLEABKID string `mapstructure:"zerossl_eab_kid"`
	ZeroSSLEABKey string `mapstructure:"zerossl_eab_key"`

	// Manual certificates
	ManualCerts []ManualCert `mapstructure:"manual_certs"`

	// Renewal settings
	RenewBefore   time.Duration `mapstructure:"renew_before"`
	CheckInterval time.Duration `mapstructure:"check_interval"`

	// Allowed domains (if empty, uses domain manager)
	AllowedDomains []string `mapstructure:"allowed_domains"`
}

// ManualCert represents a manually configured certificate.
type ManualCert struct {
	Domains  []string `mapstructure:"domains"`
	CertFile string   `mapstructure:"cert_file"`
	KeyFile  string   `mapstructure:"key_file"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ACMEDirectory: LetsEncryptProduction,
		ACMECacheDir:  "/var/lib/esp/certs",
		RenewBefore:   30 * 24 * time.Hour, // 30 days
		CheckInterval: 24 * time.Hour,
	}
}

// DomainChecker checks if a domain is valid for certificate issuance.
type DomainChecker interface {
	IsValidDomain(domain string) bool
}

// Manager handles TLS certificates.
type Manager struct {
	acmeManager   *autocert.Manager
	cache         *FileCache
	domainChecker DomainChecker
	eventBus      *event.Bus
	logger        *slog.Logger
	config        Config

	mu           sync.RWMutex
	certificates map[string]*tls.Certificate
}

// New creates a new certificate manager.
func New(cfg Config, domainChecker DomainChecker, eventBus *event.Bus, logger *slog.Logger) (*Manager, error) {
	// Create cache
	cache, err := NewFileCache(cfg.ACMECacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	m := &Manager{
		cache:         cache,
		domainChecker: domainChecker,
		eventBus:      eventBus,
		logger:        logger,
		config:        cfg,
		certificates:  make(map[string]*tls.Certificate),
	}

	// Load manual certificates
	for _, mc := range cfg.ManualCerts {
		cert, err := tls.LoadX509KeyPair(mc.CertFile, mc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate for %v: %w", mc.Domains, err)
		}
		for _, domain := range mc.Domains {
			m.certificates[domain] = &cert
			logger.Info("loaded manual certificate", "domain", domain)
		}
	}

	// Determine ACME directory
	directory := cfg.ACMEDirectory
	if cfg.UseStaging {
		directory = LetsEncryptStaging
	}
	if directory == "" {
		directory = LetsEncryptProduction
	}

	// Create ACME client
	client := &acme.Client{
		DirectoryURL: directory,
	}

	// Set up ACME manager
	m.acmeManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		Email:      cfg.ACMEEmail,
		HostPolicy: m.hostPolicy,
		Client:     client,
	}

	// Configure EAB for ZeroSSL if credentials provided
	if cfg.ZeroSSLEABKID != "" && cfg.ZeroSSLEABKey != "" {
		m.acmeManager.ExternalAccountBinding = &acme.ExternalAccountBinding{
			KID: cfg.ZeroSSLEABKID,
			Key: []byte(cfg.ZeroSSLEABKey),
		}
	}

	return m, nil
}

// GetCertificate returns a certificate for the given ClientHello.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Check manual certificates first
	m.mu.RLock()
	if cert, ok := m.certificates[hello.ServerName]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	// Try ACME
	return m.acmeManager.GetCertificate(hello)
}

// hostPolicy validates if we should get a certificate for a domain.
func (m *Manager) hostPolicy(ctx context.Context, host string) error {
	// Check allowed domains list
	if len(m.config.AllowedDomains) > 0 {
		for _, d := range m.config.AllowedDomains {
			if d == host {
				return nil
			}
		}
		return fmt.Errorf("domain not in allowed list: %s", host)
	}

	// Check domain checker
	if m.domainChecker != nil && m.domainChecker.IsValidDomain(host) {
		return nil
	}

	return fmt.Errorf("unknown domain: %s", host)
}

// TLSConfig returns a TLS config using this manager.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// HTTPHandler returns an http.Handler for ACME HTTP-01 challenges.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.acmeManager.HTTPHandler(fallback)
}

// Start starts the certificate renewal checker.
func (m *Manager) Start(ctx context.Context) {
	go m.renewalChecker(ctx)
}

// renewalChecker periodically checks for expiring certificates.
func (m *Manager) renewalChecker(ctx context.Context) {
	if m.config.CheckInterval == 0 {
		return
	}

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Initial check
	m.checkRenewals(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkRenewals(ctx)
		}
	}
}

// checkRenewals checks for certificates that need renewal.
func (m *Manager) checkRenewals(ctx context.Context) {
	m.logger.Debug("checking certificate renewals")

	// Check allowed domains
	domains := m.config.AllowedDomains

	// Also check manual certificate domains
	m.mu.RLock()
	for domain := range m.certificates {
		found := false
		for _, d := range domains {
			if d == domain {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, domain)
		}
	}
	m.mu.RUnlock()

	for _, domain := range domains {
		m.checkCertificate(ctx, domain)
	}
}

// checkCertificate checks a single domain's certificate.
func (m *Manager) checkCertificate(ctx context.Context, domain string) {
	// Get certificate info
	status := m.getCertificateStatus(ctx, domain)
	if !status.Valid {
		return
	}

	daysUntilExpiry := time.Until(status.ExpiresAt)

	// Check if renewal is needed
	if daysUntilExpiry < m.config.RenewBefore {
		m.logger.Info("certificate expiring soon",
			"domain", domain,
			"expires_at", status.ExpiresAt,
			"days_left", int(daysUntilExpiry.Hours()/24),
		)

		// Emit expiring event
		if m.eventBus != nil {
			m.eventBus.Publish(event.EventCertificateExpiring, event.CertificateExpiringEvent{
				Domain:    domain,
				ExpiresAt: status.ExpiresAt,
				DaysLeft:  int(daysUntilExpiry.Hours() / 24),
			})
		}

		// Manual certificates can't be auto-renewed
		if status.Type == "manual" {
			m.logger.Warn("manual certificate needs renewal", "domain", domain)
			return
		}

		// Trigger ACME renewal
		m.logger.Info("renewing certificate", "domain", domain)
		_, err := m.acmeManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: domain,
		})
		if err != nil {
			m.logger.Error("certificate renewal failed", "domain", domain, "error", err)
		} else {
			m.logger.Info("certificate renewed", "domain", domain)
			if m.eventBus != nil {
				m.eventBus.Publish(event.EventCertificateRenewed, event.CertificateRenewedEvent{
					Domain:    domain,
					RenewedAt: time.Now(),
				})
			}
		}
	}
}

// getCertificateStatus returns the status of a certificate.
func (m *Manager) getCertificateStatus(ctx context.Context, domain string) CertificateStatus {
	status := CertificateStatus{
		Domain: domain,
	}

	// Check manual certificates
	m.mu.RLock()
	if cert, ok := m.certificates[domain]; ok {
		m.mu.RUnlock()
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				status.Valid = true
				status.ExpiresAt = x509Cert.NotAfter
				status.IssuedAt = x509Cert.NotBefore
				status.Issuer = x509Cert.Issuer.CommonName
				status.Type = "manual"
			}
		}
		return status
	}
	m.mu.RUnlock()

	// Check ACME cache
	data, err := m.cache.Get(ctx, domain)
	if err == nil && len(data) > 0 {
		// Try to parse as PEM certificate
		cert, err := tls.X509KeyPair(data, data)
		if err == nil && len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				status.Valid = true
				status.ExpiresAt = x509Cert.NotAfter
				status.IssuedAt = x509Cert.NotBefore
				status.Issuer = x509Cert.Issuer.CommonName
				status.Type = "acme"
			}
		}
	}

	return status
}

// CertificateStatus represents certificate information.
type CertificateStatus struct {
	Domain    string    `json:"domain"`
	Valid     bool      `json:"valid"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Type      string    `json:"type"` // acme, manual
	Error     string    `json:"error,omitempty"`
}

// GetStatus returns certificate status for all configured domains.
func (m *Manager) GetStatus(ctx context.Context) []CertificateStatus {
	var statuses []CertificateStatus

	// Get all domains
	domains := make(map[string]bool)
	for _, d := range m.config.AllowedDomains {
		domains[d] = true
	}
	m.mu.RLock()
	for d := range m.certificates {
		domains[d] = true
	}
	m.mu.RUnlock()

	for domain := range domains {
		statuses = append(statuses, m.getCertificateStatus(ctx, domain))
	}

	return statuses
}

// LoadCertificate loads a certificate from files.
func (m *Manager) LoadCertificate(domains []string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, domain := range domains {
		m.certificates[domain] = &cert
		m.logger.Info("loaded certificate", "domain", domain)
	}

	return nil
}

// ReloadCertificate reloads a certificate from files.
func (m *Manager) ReloadCertificate(domains []string, certFile, keyFile string) error {
	return m.LoadCertificate(domains, certFile, keyFile)
}
