package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mnohosten/esp/internal/filter"
)

// Config holds configuration for rate limiting.
type Config struct {
	// Per-IP limits
	IPMessagesPerMinute int `mapstructure:"ip_messages_per_minute"`
	IPMessagesPerHour   int `mapstructure:"ip_messages_per_hour"`

	// Per-sender limits
	SenderMessagesPerMinute int `mapstructure:"sender_messages_per_minute"`
	SenderMessagesPerHour   int `mapstructure:"sender_messages_per_hour"`

	// Per-recipient limits
	RecipientMessagesPerMinute int `mapstructure:"recipient_messages_per_minute"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		IPMessagesPerMinute:        30,
		IPMessagesPerHour:          300,
		SenderMessagesPerMinute:    10,
		SenderMessagesPerHour:      100,
		RecipientMessagesPerMinute: 100,
	}
}

// Store tracks rate limits.
type Store interface {
	// Increment increments a counter and returns the new value.
	Increment(ctx context.Context, key string, window time.Duration) (int64, error)

	// Get returns the current counter value.
	Get(ctx context.Context, key string) (int64, error)

	// Reset clears a counter.
	Reset(ctx context.Context, key string) error
}

// windowEntry represents a sliding window entry.
type windowEntry struct {
	count     int64
	expiresAt time.Time
}

// MemoryStore is an in-memory rate limit store.
type MemoryStore struct {
	entries map[string]*windowEntry
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory rate limit store.
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		entries: make(map[string]*windowEntry),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// Increment increments a counter and returns the new value.
func (s *MemoryStore) Increment(ctx context.Context, key string, window time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, exists := s.entries[key]

	if !exists || now.After(entry.expiresAt) {
		// Create new window
		s.entries[key] = &windowEntry{
			count:     1,
			expiresAt: now.Add(window),
		}
		return 1, nil
	}

	entry.count++
	return entry.count, nil
}

// Get returns the current counter value.
func (s *MemoryStore) Get(ctx context.Context, key string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.entries[key]
	if !exists || time.Now().After(entry.expiresAt) {
		return 0, nil
	}

	return entry.count, nil
}

// Reset clears a counter.
func (s *MemoryStore) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

// cleanup periodically removes expired entries.
func (s *MemoryStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, entry := range s.entries {
			if now.After(entry.expiresAt) {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
	}
}

// Filter implements rate limiting.
type Filter struct {
	store  Store
	config Config
	logger *slog.Logger
}

// NewFilter creates a new rate limit filter.
func NewFilter(store Store, config Config, logger *slog.Logger) *Filter {
	if store == nil {
		store = NewMemoryStore()
	}

	return &Filter{
		store:  store,
		config: config,
		logger: logger,
	}
}

// Name returns the filter name.
func (f *Filter) Name() string { return "ratelimit" }

// Priority returns the filter priority.
// Rate limiting runs very early.
func (f *Filter) Priority() int { return 10 }

// Process checks rate limits for a message.
func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
	// Check IP rate limits
	if msg.ClientIP != nil {
		ip := msg.ClientIP.String()

		// Per-minute limit
		if f.config.IPMessagesPerMinute > 0 {
			key := fmt.Sprintf("ip:%s:minute", ip)
			count, err := f.store.Increment(ctx, key, time.Minute)
			if err != nil {
				return nil, err
			}
			if int(count) > f.config.IPMessagesPerMinute {
				f.logger.Info("rate limit exceeded",
					"type", "ip",
					"window", "minute",
					"ip", ip,
					"count", count,
					"limit", f.config.IPMessagesPerMinute,
				)
				return &filter.Result{
					Action: filter.ActionDefer,
					Reason: fmt.Sprintf("rate limit exceeded: %d messages per minute from IP %s", count, ip),
					Tags:   []string{"ratelimit", "ip"},
					Metadata: map[string]any{
						"ratelimit_type":  "ip",
						"ratelimit_key":   ip,
						"ratelimit_count": count,
						"ratelimit_limit": f.config.IPMessagesPerMinute,
					},
				}, nil
			}
		}

		// Per-hour limit
		if f.config.IPMessagesPerHour > 0 {
			key := fmt.Sprintf("ip:%s:hour", ip)
			count, err := f.store.Increment(ctx, key, time.Hour)
			if err != nil {
				return nil, err
			}
			if int(count) > f.config.IPMessagesPerHour {
				f.logger.Info("rate limit exceeded",
					"type", "ip",
					"window", "hour",
					"ip", ip,
					"count", count,
					"limit", f.config.IPMessagesPerHour,
				)
				return &filter.Result{
					Action: filter.ActionDefer,
					Reason: fmt.Sprintf("rate limit exceeded: %d messages per hour from IP %s", count, ip),
					Tags:   []string{"ratelimit", "ip"},
					Metadata: map[string]any{
						"ratelimit_type":  "ip",
						"ratelimit_key":   ip,
						"ratelimit_count": count,
						"ratelimit_limit": f.config.IPMessagesPerHour,
					},
				}, nil
			}
		}
	}

	// Check sender rate limits
	if msg.From != "" {
		// Per-minute limit
		if f.config.SenderMessagesPerMinute > 0 {
			key := fmt.Sprintf("sender:%s:minute", msg.From)
			count, err := f.store.Increment(ctx, key, time.Minute)
			if err != nil {
				return nil, err
			}
			if int(count) > f.config.SenderMessagesPerMinute {
				f.logger.Info("rate limit exceeded",
					"type", "sender",
					"window", "minute",
					"sender", msg.From,
					"count", count,
					"limit", f.config.SenderMessagesPerMinute,
				)
				return &filter.Result{
					Action: filter.ActionDefer,
					Reason: fmt.Sprintf("rate limit exceeded: %d messages per minute from sender %s", count, msg.From),
					Tags:   []string{"ratelimit", "sender"},
					Metadata: map[string]any{
						"ratelimit_type":  "sender",
						"ratelimit_key":   msg.From,
						"ratelimit_count": count,
						"ratelimit_limit": f.config.SenderMessagesPerMinute,
					},
				}, nil
			}
		}

		// Per-hour limit
		if f.config.SenderMessagesPerHour > 0 {
			key := fmt.Sprintf("sender:%s:hour", msg.From)
			count, err := f.store.Increment(ctx, key, time.Hour)
			if err != nil {
				return nil, err
			}
			if int(count) > f.config.SenderMessagesPerHour {
				f.logger.Info("rate limit exceeded",
					"type", "sender",
					"window", "hour",
					"sender", msg.From,
					"count", count,
					"limit", f.config.SenderMessagesPerHour,
				)
				return &filter.Result{
					Action: filter.ActionDefer,
					Reason: fmt.Sprintf("rate limit exceeded: %d messages per hour from sender %s", count, msg.From),
					Tags:   []string{"ratelimit", "sender"},
					Metadata: map[string]any{
						"ratelimit_type":  "sender",
						"ratelimit_key":   msg.From,
						"ratelimit_count": count,
						"ratelimit_limit": f.config.SenderMessagesPerHour,
					},
				}, nil
			}
		}
	}

	// Check recipient rate limits
	if f.config.RecipientMessagesPerMinute > 0 {
		for _, rcpt := range msg.To {
			key := fmt.Sprintf("rcpt:%s:minute", rcpt)
			count, err := f.store.Increment(ctx, key, time.Minute)
			if err != nil {
				return nil, err
			}
			if int(count) > f.config.RecipientMessagesPerMinute {
				f.logger.Info("rate limit exceeded",
					"type", "recipient",
					"window", "minute",
					"recipient", rcpt,
					"count", count,
					"limit", f.config.RecipientMessagesPerMinute,
				)
				return &filter.Result{
					Action: filter.ActionDefer,
					Reason: fmt.Sprintf("rate limit exceeded: %d messages per minute to recipient %s", count, rcpt),
					Tags:   []string{"ratelimit", "recipient"},
					Metadata: map[string]any{
						"ratelimit_type":  "recipient",
						"ratelimit_key":   rcpt,
						"ratelimit_count": count,
						"ratelimit_limit": f.config.RecipientMessagesPerMinute,
					},
				}, nil
			}
		}
	}

	return &filter.Result{Action: filter.ActionAccept}, nil
}
