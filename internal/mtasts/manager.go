package mtasts

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Manager orchestrates MTA-STS policy fetching, caching, and validation.
type Manager struct {
	fetcher   *Fetcher
	cache     *Cache
	validator *Validator
	logger    *slog.Logger

	// Refresh settings
	refreshInterval time.Duration

	// Background refresh
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// ManagerConfig contains configuration for the MTA-STS manager.
type ManagerConfig struct {
	Enabled          bool
	FetchTimeout     time.Duration
	MemoryCacheTTL   time.Duration
	RefreshInterval  time.Duration
}

// NewManager creates a new MTA-STS manager.
func NewManager(pool *pgxpool.Pool, logger *slog.Logger, config ManagerConfig) *Manager {
	if config.FetchTimeout == 0 {
		config.FetchTimeout = 30 * time.Second
	}
	if config.MemoryCacheTTL == 0 {
		config.MemoryCacheTTL = 5 * time.Minute
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 1 * time.Hour
	}

	fetcher := NewFetcher(logger, FetcherConfig{
		Timeout: config.FetchTimeout,
	})

	cache := NewCache(pool, logger, CacheConfig{
		MemoryTTL: config.MemoryCacheTTL,
	})

	validator := NewValidator()

	return &Manager{
		fetcher:         fetcher,
		cache:           cache,
		validator:       validator,
		logger:          logger.With("component", "mtasts.manager"),
		refreshInterval: config.RefreshInterval,
	}
}

// Start starts the background refresh loop.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.logger.Info("starting MTA-STS manager")

	m.wg.Add(1)
	go m.refreshLoop(ctx)

	return nil
}

// Stop stops the background refresh loop.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("MTA-STS manager stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// refreshLoop periodically refreshes expiring policies.
func (m *Manager) refreshLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanExpired(ctx)
		}
	}
}

// cleanExpired removes expired policies.
func (m *Manager) cleanExpired(ctx context.Context) {
	count, err := m.cache.CleanExpired(ctx)
	if err != nil {
		m.logger.Error("failed to clean expired policies", "error", err)
		return
	}
	if count > 0 {
		m.logger.Info("cleaned expired MTA-STS policies", "count", count)
	}
}

// GetPolicy retrieves the MTA-STS policy for a domain.
// It first checks the cache, then fetches if not found or expired.
func (m *Manager) GetPolicy(ctx context.Context, domain string) (*CachedPolicy, error) {
	// Check cache first
	policy, err := m.cache.Get(ctx, domain)
	if err != nil {
		m.logger.Warn("cache lookup failed", "domain", domain, "error", err)
	}

	if policy != nil && !policy.IsExpired() {
		return policy, nil
	}

	// Fetch fresh policy
	result, err := m.fetcher.Fetch(ctx, domain)
	if err != nil {
		m.logger.Error("failed to fetch MTA-STS policy", "domain", domain, "error", err)
		return policy, nil // Return cached policy if available
	}

	if result.NotFound {
		m.logger.Debug("no MTA-STS policy for domain", "domain", domain)
		return nil, nil
	}

	if result.Error != nil {
		m.logger.Warn("MTA-STS fetch error",
			"domain", domain,
			"error", result.Error,
			"dns_error", result.DNSError,
			"http_error", result.HTTPError,
		)
		m.cache.RecordFailure(ctx, domain, result.Error)
		return policy, nil // Return cached policy if available
	}

	// Cache the new policy
	if err := m.cache.Set(ctx, domain, result); err != nil {
		m.logger.Error("failed to cache policy", "domain", domain, "error", err)
	}

	// Convert to CachedPolicy for return
	expiresAt := result.FetchedAt.Add(time.Duration(result.Policy.MaxAge) * time.Second)
	return &CachedPolicy{
		Domain:        domain,
		PolicyID:      result.PolicyID,
		Mode:          result.Policy.Mode,
		MXPatterns:    result.Policy.MX,
		MaxAge:        result.Policy.MaxAge,
		FetchedAt:     result.FetchedAt,
		ExpiresAt:     expiresAt,
		LastValidated: result.FetchedAt,
	}, nil
}

// ValidateMX validates an MX host against the policy for a domain.
func (m *Manager) ValidateMX(ctx context.Context, domain, mxHost string) (*ValidationResult, error) {
	policy, err := m.GetPolicy(ctx, domain)
	if err != nil {
		return nil, err
	}

	return m.validator.ValidateMX(mxHost, policy), nil
}

// ValidateMXWithPolicy validates an MX host against a provided policy.
func (m *Manager) ValidateMXWithPolicy(mxHost string, policy *CachedPolicy) *ValidationResult {
	return m.validator.ValidateMX(mxHost, policy)
}

// ShouldEnforceTLS returns true if TLS should be enforced for a domain.
func (m *Manager) ShouldEnforceTLS(ctx context.Context, domain string) bool {
	policy, err := m.GetPolicy(ctx, domain)
	if err != nil || policy == nil {
		return false
	}
	return policy.IsEnforcing()
}

// IsTesting returns true if the domain has MTA-STS in testing mode.
func (m *Manager) IsTesting(ctx context.Context, domain string) bool {
	policy, err := m.GetPolicy(ctx, domain)
	if err != nil || policy == nil {
		return false
	}
	return policy.IsTesting()
}

// GetCachedPolicies returns all cached policies (for admin/debugging).
func (m *Manager) GetCachedPolicies(ctx context.Context, page, perPage int) ([]CachedPolicy, int, error) {
	return m.cache.GetAll(ctx, page, perPage)
}

// RefreshPolicy forces a refresh of the policy for a domain.
func (m *Manager) RefreshPolicy(ctx context.Context, domain string) (*CachedPolicy, error) {
	// Delete from cache first
	m.cache.Delete(ctx, domain)

	// Fetch fresh
	return m.GetPolicy(ctx, domain)
}
