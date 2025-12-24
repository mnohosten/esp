package event

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Subscriber handles events.
type Subscriber interface {
	// ID returns a unique identifier for this subscriber.
	ID() string

	// Handle processes an event.
	Handle(ctx context.Context, event Event) error
}

// SubscriberFunc is a function that implements Subscriber.
type SubscriberFunc struct {
	id      string
	handler func(ctx context.Context, event Event) error
}

// NewSubscriberFunc creates a new function-based subscriber.
func NewSubscriberFunc(id string, handler func(ctx context.Context, event Event) error) *SubscriberFunc {
	return &SubscriberFunc{
		id:      id,
		handler: handler,
	}
}

// ID returns the subscriber ID.
func (s *SubscriberFunc) ID() string { return s.id }

// Handle calls the handler function.
func (s *SubscriberFunc) Handle(ctx context.Context, event Event) error {
	return s.handler(ctx, event)
}

// BusConfig holds event bus configuration.
type BusConfig struct {
	Workers   int
	QueueSize int
}

// DefaultBusConfig returns the default configuration.
func DefaultBusConfig() BusConfig {
	return BusConfig{
		Workers:   4,
		QueueSize: 1000,
	}
}

// Bus is the event bus that handles pub/sub.
type Bus struct {
	subscribers map[string][]Subscriber
	queue       chan Event
	config      BusConfig
	logger      *slog.Logger
	mu          sync.RWMutex
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	started     bool
}

// NewBus creates a new event bus.
func NewBus(config BusConfig, logger *slog.Logger) *Bus {
	ctx, cancel := context.WithCancel(context.Background())
	return &Bus{
		subscribers: make(map[string][]Subscriber),
		queue:       make(chan Event, config.QueueSize),
		config:      config,
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Subscribe adds a subscriber for an event type.
// Use "*" to subscribe to all events.
func (b *Bus) Subscribe(eventType string, subscriber Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.subscribers[eventType] = append(b.subscribers[eventType], subscriber)
	b.logger.Debug("subscriber added",
		"event_type", eventType,
		"subscriber_id", subscriber.ID(),
	)
}

// Unsubscribe removes a subscriber.
func (b *Bus) Unsubscribe(eventType string, subscriberID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	subs := b.subscribers[eventType]
	for i, s := range subs {
		if s.ID() == subscriberID {
			b.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
			b.logger.Debug("subscriber removed",
				"event_type", eventType,
				"subscriber_id", subscriberID,
			)
			return
		}
	}
}

// Subscribers returns the count of subscribers for an event type.
func (b *Bus) Subscribers(eventType string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := len(b.subscribers[eventType])
	count += len(b.subscribers["*"])
	return count
}

// Publish sends an event to the bus asynchronously.
func (b *Bus) Publish(eventType string, data any) {
	event := NewEvent(eventType, data)

	select {
	case b.queue <- event:
		b.logger.Debug("event published", "type", eventType)
	default:
		b.logger.Warn("event queue full, dropping event", "type", eventType)
	}
}

// PublishEvent sends an existing event to the bus.
func (b *Bus) PublishEvent(event Event) {
	select {
	case b.queue <- event:
		b.logger.Debug("event published", "type", event.Type())
	default:
		b.logger.Warn("event queue full, dropping event", "type", event.Type())
	}
}

// PublishSync publishes and waits for all handlers to complete.
func (b *Bus) PublishSync(ctx context.Context, eventType string, data any) error {
	event := NewEvent(eventType, data)
	return b.dispatch(ctx, event)
}

// Start starts the event bus workers.
func (b *Bus) Start() {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return
	}
	b.started = true
	b.mu.Unlock()

	b.logger.Info("starting event bus", "workers", b.config.Workers)

	for i := 0; i < b.config.Workers; i++ {
		b.wg.Add(1)
		go b.worker(i)
	}
}

// Stop stops the event bus gracefully.
func (b *Bus) Stop() {
	b.logger.Info("stopping event bus")
	b.cancel()
	close(b.queue)
	b.wg.Wait()
	b.logger.Info("event bus stopped")
}

// worker processes events from the queue.
func (b *Bus) worker(id int) {
	defer b.wg.Done()

	for event := range b.queue {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		if err := b.dispatch(b.ctx, event); err != nil {
			b.logger.Error("event dispatch failed",
				"worker", id,
				"event", event.Type(),
				"error", err,
			)
		}
	}
}

// dispatch sends an event to all matching subscribers.
func (b *Bus) dispatch(ctx context.Context, event Event) error {
	b.mu.RLock()
	// Get specific subscribers
	subs := make([]Subscriber, 0, len(b.subscribers[event.Type()])+len(b.subscribers["*"]))
	subs = append(subs, b.subscribers[event.Type()]...)
	// Get wildcard subscribers
	subs = append(subs, b.subscribers["*"]...)
	b.mu.RUnlock()

	if len(subs) == 0 {
		return nil
	}

	var errs []error
	for _, sub := range subs {
		// Create a timeout context for each subscriber
		subCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		if err := sub.Handle(subCtx, event); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sub.ID(), err))
			b.logger.Warn("subscriber error",
				"subscriber", sub.ID(),
				"event", event.Type(),
				"error", err,
			)
		}

		cancel()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// QueueLength returns the current queue length.
func (b *Bus) QueueLength() int {
	return len(b.queue)
}

// QueueCapacity returns the queue capacity.
func (b *Bus) QueueCapacity() int {
	return cap(b.queue)
}
