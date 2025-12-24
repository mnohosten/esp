# Phase 8: Certificate Management

## Overview

**Goal**: Implement automatic TLS certificate acquisition and renewal using ACME protocol.

**Dependencies**: Phase 1 (Foundation)

**Estimated Complexity**: Low-Medium

## Prerequisites

- Phase 1 completed
- Understanding of ACME protocol
- Domain DNS properly configured

## Deliverables

1. ACME client integration
2. Let's Encrypt support
3. ZeroSSL support
4. Automatic certificate renewal
5. Per-domain certificate management
6. Certificate status monitoring

## Core Components

### 1. Certificate Manager

**File**: `internal/cert/manager.go`

```go
// Manager handles TLS certificates
type Manager struct {
    acmeManager  *autocert.Manager
    cache        Cache
    domains      *domain.Manager
    eventBus     *event.Bus
    logger       *slog.Logger
    config       Config
    mu           sync.RWMutex
    certificates map[string]*tls.Certificate
}

// Config for certificate management
type Config struct {
    // ACME settings
    ACMEEmail       string        `mapstructure:"acme_email"`
    ACMEDirectory   string        `mapstructure:"acme_directory"` // Let's Encrypt or ZeroSSL
    ACMECacheDir    string        `mapstructure:"acme_cache_dir"`
    UseStaging      bool          `mapstructure:"use_staging"`

    // Manual certificates
    ManualCerts     []ManualCert  `mapstructure:"manual_certs"`

    // Renewal settings
    RenewBefore     time.Duration `mapstructure:"renew_before"`
    CheckInterval   time.Duration `mapstructure:"check_interval"`
}

// ManualCert for manually provided certificates
type ManualCert struct {
    Domains  []string `mapstructure:"domains"`
    CertFile string   `mapstructure:"cert_file"`
    KeyFile  string   `mapstructure:"key_file"`
}

// New creates a new certificate manager
func New(cfg Config, domains *domain.Manager, eventBus *event.Bus, logger *slog.Logger) (*Manager, error) {
    cache, err := NewFileCache(cfg.ACMECacheDir)
    if err != nil {
        return nil, fmt.Errorf("failed to create cache: %w", err)
    }

    m := &Manager{
        cache:        cache,
        domains:      domains,
        eventBus:     eventBus,
        logger:       logger,
        config:       cfg,
        certificates: make(map[string]*tls.Certificate),
    }

    // Load manual certificates
    for _, mc := range cfg.ManualCerts {
        cert, err := tls.LoadX509KeyPair(mc.CertFile, mc.KeyFile)
        if err != nil {
            return nil, fmt.Errorf("failed to load certificate for %v: %w", mc.Domains, err)
        }
        for _, domain := range mc.Domains {
            m.certificates[domain] = &cert
        }
    }

    // Set up ACME manager
    directory := cfg.ACMEDirectory
    if cfg.UseStaging {
        directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
    }
    if directory == "" {
        directory = autocert.DefaultACMEDirectory // Let's Encrypt production
    }

    m.acmeManager = &autocert.Manager{
        Prompt:      autocert.AcceptTOS,
        Cache:       cache,
        Email:       cfg.ACMEEmail,
        HostPolicy:  m.hostPolicy,
        Client:      &acme.Client{DirectoryURL: directory},
    }

    return m, nil
}

// GetCertificate returns a certificate for the given ClientHello
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    m.mu.RLock()
    if cert, ok := m.certificates[hello.ServerName]; ok {
        m.mu.RUnlock()
        return cert, nil
    }
    m.mu.RUnlock()

    // Try ACME
    return m.acmeManager.GetCertificate(hello)
}

// hostPolicy validates if we should get a certificate for a domain
func (m *Manager) hostPolicy(ctx context.Context, host string) error {
    // Check if domain is configured in our system
    if m.domains.IsValidDomain(host) {
        return nil
    }
    return fmt.Errorf("unknown domain: %s", host)
}

// TLSConfig returns a TLS config using this manager
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

// Start starts the certificate renewal checker
func (m *Manager) Start(ctx context.Context) {
    go m.renewalChecker(ctx)
}

// renewalChecker periodically checks for expiring certificates
func (m *Manager) renewalChecker(ctx context.Context) {
    ticker := time.NewTicker(m.config.CheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.checkRenewals(ctx)
        }
    }
}

// checkRenewals checks for certificates that need renewal
func (m *Manager) checkRenewals(ctx context.Context) {
    domains, err := m.domains.ListAll(ctx)
    if err != nil {
        m.logger.Error("failed to list domains", "error", err)
        return
    }

    for _, d := range domains {
        cert, err := m.cache.Get(ctx, d.Name)
        if err != nil {
            continue // No cached cert
        }

        x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
        if err != nil {
            continue
        }

        daysUntilExpiry := time.Until(x509Cert.NotAfter)

        // Emit expiring event
        if daysUntilExpiry < m.config.RenewBefore {
            m.eventBus.Publish(event.EventCertificateExpiring, event.CertificateEvent{
                Domain:    d.Name,
                ExpiresAt: x509Cert.NotAfter,
                Issuer:    x509Cert.Issuer.CommonName,
            })

            // Trigger renewal by requesting new cert
            m.logger.Info("renewing certificate", "domain", d.Name)
            _, err := m.acmeManager.GetCertificate(&tls.ClientHelloInfo{
                ServerName: d.Name,
            })
            if err != nil {
                m.logger.Error("certificate renewal failed", "domain", d.Name, "error", err)
            } else {
                m.eventBus.Publish(event.EventCertificateRenewed, event.CertificateEvent{
                    Domain:    d.Name,
                    ExpiresAt: x509Cert.NotAfter.Add(90 * 24 * time.Hour), // Approximate
                    RenewedAt: time.Now(),
                })
            }
        }
    }
}

// GetStatus returns certificate status for all domains
func (m *Manager) GetStatus(ctx context.Context) ([]CertificateStatus, error) {
    var statuses []CertificateStatus

    domains, err := m.domains.ListAll(ctx)
    if err != nil {
        return nil, err
    }

    for _, d := range domains {
        status := CertificateStatus{
            Domain: d.Name,
        }

        // Check manual certs first
        m.mu.RLock()
        if cert, ok := m.certificates[d.Name]; ok {
            m.mu.RUnlock()
            x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
            if x509Cert != nil {
                status.Valid = true
                status.ExpiresAt = x509Cert.NotAfter
                status.Issuer = x509Cert.Issuer.CommonName
                status.Type = "manual"
            }
            statuses = append(statuses, status)
            continue
        }
        m.mu.RUnlock()

        // Check ACME cache
        cert, err := m.cache.Get(ctx, d.Name)
        if err == nil {
            x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
            if x509Cert != nil {
                status.Valid = true
                status.ExpiresAt = x509Cert.NotAfter
                status.Issuer = x509Cert.Issuer.CommonName
                status.Type = "acme"
            }
        }

        statuses = append(statuses, status)
    }

    return statuses, nil
}

// CertificateStatus represents certificate info
type CertificateStatus struct {
    Domain    string    `json:"domain"`
    Valid     bool      `json:"valid"`
    ExpiresAt time.Time `json:"expires_at,omitempty"`
    Issuer    string    `json:"issuer,omitempty"`
    Type      string    `json:"type"` // acme, manual
    Error     string    `json:"error,omitempty"`
}
```

### 2. Certificate Cache

**File**: `internal/cert/cache.go`

```go
// Cache interface for certificate storage
type Cache interface {
    Get(ctx context.Context, key string) (*tls.Certificate, error)
    Put(ctx context.Context, key string, cert *tls.Certificate) error
    Delete(ctx context.Context, key string) error
}

// FileCache stores certificates on disk
type FileCache struct {
    dir string
}

// NewFileCache creates a new file-based cache
func NewFileCache(dir string) (*FileCache, error) {
    if err := os.MkdirAll(dir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create cache dir: %w", err)
    }
    return &FileCache{dir: dir}, nil
}

// Implement autocert.Cache interface
func (c *FileCache) Get(ctx context.Context, key string) ([]byte, error) {
    path := filepath.Join(c.dir, key)
    data, err := os.ReadFile(path)
    if os.IsNotExist(err) {
        return nil, autocert.ErrCacheMiss
    }
    return data, err
}

func (c *FileCache) Put(ctx context.Context, key string, data []byte) error {
    path := filepath.Join(c.dir, key)
    return os.WriteFile(path, data, 0600)
}

func (c *FileCache) Delete(ctx context.Context, key string) error {
    path := filepath.Join(c.dir, key)
    return os.Remove(path)
}
```

### 3. ZeroSSL Support

**File**: `internal/cert/zerossl.go`

```go
// ZeroSSL ACME directory
const ZeroSSLDirectory = "https://acme.zerossl.com/v2/DV90"

// ZeroSSLManager adds ZeroSSL-specific handling
type ZeroSSLManager struct {
    *Manager
    eabKID      string
    eabHMACKey  string
}

// NewZeroSSL creates a manager configured for ZeroSSL
func NewZeroSSL(cfg Config, domains *domain.Manager, eventBus *event.Bus, logger *slog.Logger) (*ZeroSSLManager, error) {
    cfg.ACMEDirectory = ZeroSSLDirectory

    base, err := New(cfg, domains, eventBus, logger)
    if err != nil {
        return nil, err
    }

    // ZeroSSL requires EAB credentials
    // These should be obtained from ZeroSSL dashboard
    zm := &ZeroSSLManager{
        Manager:    base,
        eabKID:     cfg.ZeroSSLEABKID,
        eabHMACKey: cfg.ZeroSSLEABKey,
    }

    // Configure EAB
    if zm.eabKID != "" && zm.eabHMACKey != "" {
        zm.acmeManager.ExternalAccountBinding = &acme.ExternalAccountBinding{
            KID: zm.eabKID,
            Key: zm.eabHMACKey,
        }
    }

    return zm, nil
}
```

### 4. HTTP Challenge Handler

**File**: `internal/cert/challenge.go`

```go
// ChallengeHandler handles ACME HTTP-01 challenges
type ChallengeHandler struct {
    manager *Manager
}

// NewChallengeHandler creates a challenge handler
func NewChallengeHandler(manager *Manager) *ChallengeHandler {
    return &ChallengeHandler{manager: manager}
}

// Handler returns an http.Handler for /.well-known/acme-challenge/
func (h *ChallengeHandler) Handler() http.Handler {
    return h.manager.acmeManager.HTTPHandler(nil)
}

// ServeHTTP handles challenge requests
func (h *ChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    h.manager.acmeManager.HTTPHandler(nil).ServeHTTP(w, r)
}
```

## Task Breakdown

### ACME Integration
- [ ] Set up autocert manager
- [ ] Implement host policy
- [ ] Configure ACME directory (Let's Encrypt)
- [ ] Handle HTTP-01 challenges
- [ ] Implement certificate caching

### ZeroSSL Support
- [ ] Add ZeroSSL directory configuration
- [ ] Handle EAB credentials
- [ ] Test ZeroSSL certificate issuance

### Certificate Renewal
- [ ] Implement renewal checker
- [ ] Calculate renewal timing
- [ ] Trigger automatic renewal
- [ ] Emit renewal events

### Manual Certificates
- [ ] Support manual cert/key loading
- [ ] Validate certificate chain
- [ ] Handle certificate reload

### Monitoring
- [ ] Certificate status API endpoint
- [ ] Expiration warnings
- [ ] Metrics for certificate age

### TLS Configuration
- [ ] Configure secure cipher suites
- [ ] Set minimum TLS version
- [ ] Support multiple domains

## Configuration

```yaml
security:
  tls:
    # Manual certificates (optional)
    cert_file: ""
    key_file: ""

    # ACME settings
    auto_tls: true
    acme_email: "admin@example.com"

    # ACME provider: "letsencrypt" or "zerossl"
    acme_provider: "letsencrypt"

    # Use staging server for testing
    acme_staging: false

    # Certificate cache directory
    acme_dir: "/var/lib/esp/certs"

    # ZeroSSL EAB credentials (if using ZeroSSL)
    zerossl_eab_kid: ""
    zerossl_eab_key: ""

    # Renewal settings
    renew_before: 720h  # 30 days
    check_interval: 24h
```

## DNS Requirements

For ACME to work, the domain must:
1. Have valid A/AAAA records pointing to the server
2. Port 80 must be accessible for HTTP-01 challenges
3. Or use DNS-01 challenge (requires DNS provider integration)

## Testing

### Unit Tests
- Certificate loading
- Cache operations
- Host policy validation

### Integration Tests
- Let's Encrypt staging
- Certificate renewal
- Manual cert loading

### Test with Staging
```bash
# Enable staging in config
acme_staging: true

# Request certificate
curl -I https://mail.example.com:465

# Check certificate
openssl s_client -connect mail.example.com:465 -servername mail.example.com
```

## Completion Criteria

- [ ] ACME client requests certificates
- [ ] Let's Encrypt certificates work
- [ ] ZeroSSL certificates work
- [ ] Automatic renewal works
- [ ] Manual certificates supported
- [ ] Certificate status reported
- [ ] Events emitted for expiring/renewed
- [ ] All tests pass

## Next Phase

Once Phase 8 is complete, proceed to [Phase 9: LLM Integration](./phase-09-llm.md).
