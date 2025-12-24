package filter

import (
	"context"
	"log/slog"
	"sort"
	"sync"
)

// FilterErrorEvent is emitted when a filter encounters an error.
type FilterErrorEvent struct {
	Filter    string `json:"filter"`
	MessageID string `json:"message_id"`
	Error     string `json:"error"`
}

// FilterMatchEvent is emitted when a filter matches a message.
type FilterMatchEvent struct {
	Filter    string   `json:"filter"`
	MessageID string   `json:"message_id"`
	Action    Action   `json:"action"`
	Score     float64  `json:"score"`
	Tags      []string `json:"tags"`
}

// EventPublisher publishes filter events.
type EventPublisher interface {
	Publish(topic string, event any)
}

// ChainConfig holds configuration for the filter chain.
type ChainConfig struct {
	// FailOpen continues processing if a filter errors.
	// If false, filter errors will stop processing.
	FailOpen bool
}

// Chain orchestrates filter execution.
type Chain struct {
	filters  []Filter
	config   ChainConfig
	eventBus EventPublisher
	logger   *slog.Logger
	mu       sync.RWMutex
}

// NewChain creates a new filter chain.
func NewChain(eventBus EventPublisher, logger *slog.Logger) *Chain {
	return &Chain{
		filters: make([]Filter, 0),
		config: ChainConfig{
			FailOpen: true, // Default to fail-open
		},
		eventBus: eventBus,
		logger:   logger,
	}
}

// SetConfig updates the chain configuration.
func (c *Chain) SetConfig(config ChainConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
}

// Register adds a filter to the chain.
func (c *Chain) Register(filter Filter) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if filter already exists
	for i, f := range c.filters {
		if f.Name() == filter.Name() {
			// Replace existing filter
			c.filters[i] = filter
			c.logger.Info("filter replaced", "name", filter.Name())
			return
		}
	}

	c.filters = append(c.filters, filter)
	c.logger.Info("filter registered",
		"name", filter.Name(),
		"priority", filter.Priority(),
	)
}

// Unregister removes a filter from the chain.
func (c *Chain) Unregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, f := range c.filters {
		if f.Name() == name {
			c.filters = append(c.filters[:i], c.filters[i+1:]...)
			c.logger.Info("filter unregistered", "name", name)
			return
		}
	}
}

// Filters returns a copy of all registered filters.
func (c *Chain) Filters() []Filter {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Filter, len(c.filters))
	copy(result, c.filters)
	return result
}

// sortedFilters returns filters sorted by priority.
func (c *Chain) sortedFilters() []Filter {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sorted := make([]Filter, len(c.filters))
	copy(sorted, c.filters)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority() < sorted[j].Priority()
	})

	return sorted
}

// Process runs all filters on a message.
func (c *Chain) Process(ctx context.Context, msg *Message) (*Result, error) {
	finalResult := NewResult()
	filters := c.sortedFilters()

	c.logger.Debug("processing message through filter chain",
		"message_id", msg.ID,
		"filter_count", len(filters),
	)

	for _, filter := range filters {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		c.logger.Debug("running filter",
			"filter", filter.Name(),
			"message_id", msg.ID,
		)

		result, err := filter.Process(ctx, msg)
		if err != nil {
			c.logger.Error("filter error",
				"filter", filter.Name(),
				"message_id", msg.ID,
				"error", err,
			)

			// Emit error event
			if c.eventBus != nil {
				c.eventBus.Publish("filter.error", FilterErrorEvent{
					Filter:    filter.Name(),
					MessageID: msg.ID,
					Error:     err.Error(),
				})
			}

			// Check fail-open policy
			c.mu.RLock()
			failOpen := c.config.FailOpen
			c.mu.RUnlock()

			if !failOpen {
				return nil, err
			}
			continue
		}

		if result == nil {
			continue
		}

		// Merge results
		finalResult.Merge(result)

		c.logger.Debug("filter processed",
			"filter", filter.Name(),
			"message_id", msg.ID,
			"action", result.Action.String(),
			"score", result.Score,
		)

		// Emit filter match event if action is not accept or there are tags
		if c.eventBus != nil && (result.Action != ActionAccept || len(result.Tags) > 0) {
			c.eventBus.Publish("filter.matched", FilterMatchEvent{
				Filter:    filter.Name(),
				MessageID: msg.ID,
				Action:    result.Action,
				Score:     result.Score,
				Tags:      result.Tags,
			})
		}

		// Stop on reject/discard
		if result.Action == ActionReject || result.Action == ActionDiscard {
			c.logger.Info("filter chain stopped",
				"filter", filter.Name(),
				"message_id", msg.ID,
				"action", result.Action.String(),
				"reason", result.Reason,
			)
			break
		}
	}

	c.logger.Debug("filter chain complete",
		"message_id", msg.ID,
		"final_action", finalResult.Action.String(),
		"final_score", finalResult.Score,
	)

	return finalResult, nil
}
