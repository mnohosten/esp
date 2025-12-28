package dmarc

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Collector collects DMARC authentication results for aggregate report generation.
type Collector struct {
	store   *Store
	logger  *slog.Logger
	enabled bool

	// Buffer for batching inserts
	mu      sync.Mutex
	buffer  []*AuthResult
	bufSize int
}

// CollectorConfig contains configuration for the collector.
type CollectorConfig struct {
	Enabled   bool
	BatchSize int
}

// NewCollector creates a new DMARC result collector.
func NewCollector(store *Store, logger *slog.Logger, config CollectorConfig) *Collector {
	bufSize := config.BatchSize
	if bufSize <= 0 {
		bufSize = 100
	}

	return &Collector{
		store:   store,
		logger:  logger.With("component", "dmarc.collector"),
		enabled: config.Enabled,
		buffer:  make([]*AuthResult, 0, bufSize),
		bufSize: bufSize,
	}
}

// CollectedResult represents authentication data to be collected.
type CollectedResult struct {
	MessageID          string
	HeaderFromDomain   string
	EnvelopeFromDomain string
	EnvelopeToDomain   string
	SourceIP           net.IP

	// SPF results
	SPFResult  string
	SPFDomain  string
	SPFAligned bool

	// DKIM results
	DKIMResults []DKIMResultJSON
	DKIMAligned bool

	// DMARC results
	DMARCResult string
	DMARCPolicy string
	Disposition string
}

// Record records an authentication result for future DMARC report generation.
func (c *Collector) Record(ctx context.Context, result *CollectedResult) error {
	if !c.enabled {
		return nil
	}

	if result.HeaderFromDomain == "" {
		return nil
	}

	authResult := &AuthResult{
		MessageID:          result.MessageID,
		HeaderFromDomain:   result.HeaderFromDomain,
		EnvelopeFromDomain: result.EnvelopeFromDomain,
		EnvelopeToDomain:   result.EnvelopeToDomain,
		SourceIP:           result.SourceIP,
		SPFResult:          result.SPFResult,
		SPFDomain:          result.SPFDomain,
		SPFAligned:         result.SPFAligned,
		DKIMResults:        result.DKIMResults,
		DKIMAligned:        result.DKIMAligned,
		DMARCResult:        result.DMARCResult,
		DMARCPolicy:        result.DMARCPolicy,
		Disposition:        result.Disposition,
		ReceivedAt:         time.Now(),
		ReportDate:         time.Now().UTC().Truncate(24 * time.Hour),
	}

	c.mu.Lock()
	c.buffer = append(c.buffer, authResult)
	shouldFlush := len(c.buffer) >= c.bufSize
	c.mu.Unlock()

	if shouldFlush {
		return c.Flush(ctx)
	}

	return nil
}

// Flush writes buffered results to the database.
func (c *Collector) Flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return nil
	}
	toFlush := c.buffer
	c.buffer = make([]*AuthResult, 0, c.bufSize)
	c.mu.Unlock()

	for _, result := range toFlush {
		if err := c.store.SaveAuthResult(ctx, result); err != nil {
			c.logger.Error("failed to save auth result",
				"domain", result.HeaderFromDomain,
				"error", err,
			)
			// Continue with other results
		}
	}

	c.logger.Debug("flushed auth results", "count", len(toFlush))
	return nil
}

// Enabled returns whether the collector is enabled.
func (c *Collector) Enabled() bool {
	return c.enabled
}

// SetEnabled enables or disables the collector.
func (c *Collector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// Close flushes any remaining results and closes the collector.
func (c *Collector) Close(ctx context.Context) error {
	return c.Flush(ctx)
}
