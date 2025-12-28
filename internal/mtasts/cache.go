package mtasts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Cache provides a database-backed cache for MTA-STS policies.
type Cache struct {
	pool   *pgxpool.Pool
	logger *slog.Logger

	// In-memory cache for hot policies
	mu       sync.RWMutex
	memCache map[string]*CachedPolicy
	memTTL   time.Duration
}

// CacheConfig contains configuration for the cache.
type CacheConfig struct {
	MemoryTTL time.Duration // How long to keep policies in memory
}

// NewCache creates a new MTA-STS policy cache.
func NewCache(pool *pgxpool.Pool, logger *slog.Logger, config CacheConfig) *Cache {
	if config.MemoryTTL == 0 {
		config.MemoryTTL = 5 * time.Minute
	}

	return &Cache{
		pool:     pool,
		logger:   logger.With("component", "mtasts.cache"),
		memCache: make(map[string]*CachedPolicy),
		memTTL:   config.MemoryTTL,
	}
}

// Get retrieves a cached policy for a domain.
func (c *Cache) Get(ctx context.Context, domain string) (*CachedPolicy, error) {
	// Check memory cache first
	c.mu.RLock()
	if policy, ok := c.memCache[domain]; ok {
		c.mu.RUnlock()
		if !policy.IsExpired() {
			return policy, nil
		}
		// Expired in memory, check database
	} else {
		c.mu.RUnlock()
	}

	// Check database
	policy, err := c.getFromDB(ctx, domain)
	if err != nil {
		return nil, err
	}

	if policy != nil && !policy.IsExpired() {
		// Update memory cache
		c.mu.Lock()
		c.memCache[domain] = policy
		c.mu.Unlock()
		return policy, nil
	}

	return nil, nil
}

// getFromDB retrieves a policy from the database.
func (c *Cache) getFromDB(ctx context.Context, domain string) (*CachedPolicy, error) {
	var policy CachedPolicy
	err := c.pool.QueryRow(ctx, `
		SELECT id, domain, policy_mode, mx_patterns, max_age, policy_id,
			   fetched_at, expires_at, last_validated, validation_errors, fetch_failures
		FROM mta_sts_policies
		WHERE domain = $1`, domain,
	).Scan(
		&policy.ID, &policy.Domain, &policy.Mode, &policy.MXPatterns, &policy.MaxAge,
		&policy.PolicyID, &policy.FetchedAt, &policy.ExpiresAt, &policy.LastValidated,
		&policy.ValidationError, &policy.FetchFailures,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy from database: %w", err)
	}

	return &policy, nil
}

// Set stores a policy in the cache.
func (c *Cache) Set(ctx context.Context, domain string, result *FetchResult) error {
	if result.Policy == nil {
		return nil
	}

	expiresAt := result.FetchedAt.Add(time.Duration(result.Policy.MaxAge) * time.Second)

	policy := &CachedPolicy{
		ID:            uuid.New(),
		Domain:        domain,
		PolicyID:      result.PolicyID,
		Mode:          result.Policy.Mode,
		MXPatterns:    result.Policy.MX,
		MaxAge:        result.Policy.MaxAge,
		FetchedAt:     result.FetchedAt,
		ExpiresAt:     expiresAt,
		LastValidated: result.FetchedAt,
	}

	// Save to database
	_, err := c.pool.Exec(ctx, `
		INSERT INTO mta_sts_policies (
			id, domain, policy_mode, mx_patterns, max_age, policy_id,
			fetched_at, expires_at, last_validated
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (domain) DO UPDATE SET
			policy_mode = EXCLUDED.policy_mode,
			mx_patterns = EXCLUDED.mx_patterns,
			max_age = EXCLUDED.max_age,
			policy_id = EXCLUDED.policy_id,
			fetched_at = EXCLUDED.fetched_at,
			expires_at = EXCLUDED.expires_at,
			last_validated = EXCLUDED.last_validated,
			fetch_failures = 0,
			updated_at = NOW()`,
		policy.ID, policy.Domain, policy.Mode, policy.MXPatterns, policy.MaxAge,
		policy.PolicyID, policy.FetchedAt, policy.ExpiresAt, policy.LastValidated,
	)
	if err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}

	// Update memory cache
	c.mu.Lock()
	c.memCache[domain] = policy
	c.mu.Unlock()

	c.logger.Debug("cached MTA-STS policy",
		"domain", domain,
		"mode", policy.Mode,
		"expires_at", policy.ExpiresAt,
	)

	return nil
}

// RecordFailure records a fetch failure for a domain.
func (c *Cache) RecordFailure(ctx context.Context, domain string, err error) error {
	_, dbErr := c.pool.Exec(ctx, `
		INSERT INTO mta_sts_policies (domain, policy_mode, mx_patterns, max_age, fetched_at, expires_at, fetch_failures, validation_errors)
		VALUES ($1, 'none', '{}', 0, NOW(), NOW(), 1, $2)
		ON CONFLICT (domain) DO UPDATE SET
			fetch_failures = mta_sts_policies.fetch_failures + 1,
			validation_errors = $2,
			updated_at = NOW()`,
		domain, err.Error(),
	)
	return dbErr
}

// Delete removes a policy from the cache.
func (c *Cache) Delete(ctx context.Context, domain string) error {
	// Remove from memory
	c.mu.Lock()
	delete(c.memCache, domain)
	c.mu.Unlock()

	// Remove from database
	_, err := c.pool.Exec(ctx, `DELETE FROM mta_sts_policies WHERE domain = $1`, domain)
	return err
}

// CleanExpired removes expired policies from the cache.
func (c *Cache) CleanExpired(ctx context.Context) (int, error) {
	// Clean memory cache
	c.mu.Lock()
	for domain, policy := range c.memCache {
		if policy.IsExpired() {
			delete(c.memCache, domain)
		}
	}
	c.mu.Unlock()

	// Clean database (keep for a grace period for logging/debugging)
	gracePeriod := 7 * 24 * time.Hour // Keep expired policies for 7 days
	result, err := c.pool.Exec(ctx, `
		DELETE FROM mta_sts_policies
		WHERE expires_at < $1`,
		time.Now().Add(-gracePeriod),
	)
	if err != nil {
		return 0, err
	}

	return int(result.RowsAffected()), nil
}

// GetAll returns all cached policies (for debugging/admin).
func (c *Cache) GetAll(ctx context.Context, page, perPage int) ([]CachedPolicy, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	rows, err := c.pool.Query(ctx, `
		SELECT id, domain, policy_mode, mx_patterns, max_age, policy_id,
			   fetched_at, expires_at, last_validated, validation_errors, fetch_failures
		FROM mta_sts_policies
		ORDER BY domain
		LIMIT $1 OFFSET $2`,
		perPage, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var policies []CachedPolicy
	for rows.Next() {
		var p CachedPolicy
		err := rows.Scan(
			&p.ID, &p.Domain, &p.Mode, &p.MXPatterns, &p.MaxAge, &p.PolicyID,
			&p.FetchedAt, &p.ExpiresAt, &p.LastValidated, &p.ValidationError, &p.FetchFailures,
		)
		if err != nil {
			return nil, 0, err
		}
		policies = append(policies, p)
	}

	var total int
	c.pool.QueryRow(ctx, `SELECT COUNT(*) FROM mta_sts_policies`).Scan(&total)

	return policies, total, nil
}
