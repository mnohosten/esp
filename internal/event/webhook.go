package event

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Webhook represents a webhook configuration.
type Webhook struct {
	ID           uuid.UUID  `json:"id"`
	DomainID     *uuid.UUID `json:"domain_id,omitempty"`
	Name         string     `json:"name"`
	URL          string     `json:"url"`
	Events       []string   `json:"events"`
	Secret       string     `json:"secret,omitempty"`
	Enabled      bool       `json:"enabled"`
	FailureCount int        `json:"failure_count"`
}

// WebhookStore provides webhook persistence.
type WebhookStore interface {
	// FindByEvent returns webhooks subscribed to an event type.
	FindByEvent(ctx context.Context, eventType string) ([]*Webhook, error)

	// UpdateLastTriggered updates the last triggered timestamp.
	UpdateLastTriggered(ctx context.Context, webhookID uuid.UUID) error

	// IncrementFailure increments the failure count.
	IncrementFailure(ctx context.Context, webhookID uuid.UUID) error

	// ResetFailure resets the failure count.
	ResetFailure(ctx context.Context, webhookID uuid.UUID) error
}

// WebhookDelivery represents a pending webhook delivery.
type WebhookDelivery struct {
	Webhook   *Webhook
	Event     Event
	Attempt   int
	NextRetry time.Time
}

// WebhookDispatcher sends events to webhooks.
type WebhookDispatcher struct {
	id         string
	store      WebhookStore
	httpClient *http.Client
	queue      chan *WebhookDelivery
	retryQueue chan *WebhookDelivery
	logger     *slog.Logger
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	maxRetries int
}

// NewWebhookDispatcher creates a new webhook dispatcher.
func NewWebhookDispatcher(store WebhookStore, logger *slog.Logger) *WebhookDispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &WebhookDispatcher{
		id:    "webhook-dispatcher",
		store: store,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		queue:      make(chan *WebhookDelivery, 1000),
		retryQueue: make(chan *WebhookDelivery, 1000),
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		maxRetries: 5,
	}
}

// ID returns the subscriber ID.
func (d *WebhookDispatcher) ID() string { return d.id }

// Handle queues webhook deliveries for an event.
func (d *WebhookDispatcher) Handle(ctx context.Context, event Event) error {
	if d.store == nil {
		return nil
	}

	webhooks, err := d.store.FindByEvent(ctx, event.Type())
	if err != nil {
		return fmt.Errorf("failed to find webhooks: %w", err)
	}

	for _, webhook := range webhooks {
		if !webhook.Enabled {
			continue
		}

		// Skip webhooks with too many failures
		if webhook.FailureCount >= 10 {
			d.logger.Debug("skipping webhook due to failures",
				"webhook_id", webhook.ID,
				"failure_count", webhook.FailureCount,
			)
			continue
		}

		select {
		case d.queue <- &WebhookDelivery{
			Webhook: webhook,
			Event:   event,
			Attempt: 1,
		}:
		default:
			d.logger.Warn("webhook queue full, dropping delivery",
				"webhook_id", webhook.ID,
				"event", event.Type(),
			)
		}
	}

	return nil
}

// Start starts the webhook dispatcher workers.
func (d *WebhookDispatcher) Start() {
	d.logger.Info("starting webhook dispatcher")

	// Main delivery workers
	for i := 0; i < 5; i++ {
		d.wg.Add(1)
		go d.deliveryWorker(i)
	}

	// Retry worker
	d.wg.Add(1)
	go d.retryWorker()
}

// Stop stops the webhook dispatcher.
func (d *WebhookDispatcher) Stop() {
	d.logger.Info("stopping webhook dispatcher")
	d.cancel()
	close(d.queue)
	close(d.retryQueue)
	d.wg.Wait()
	d.logger.Info("webhook dispatcher stopped")
}

// deliveryWorker processes webhook deliveries.
func (d *WebhookDispatcher) deliveryWorker(id int) {
	defer d.wg.Done()

	for delivery := range d.queue {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		if err := d.deliver(d.ctx, delivery); err != nil {
			d.logger.Error("webhook delivery failed",
				"worker", id,
				"webhook_id", delivery.Webhook.ID,
				"webhook_name", delivery.Webhook.Name,
				"attempt", delivery.Attempt,
				"error", err,
			)

			// Schedule retry
			if delivery.Attempt < d.maxRetries {
				delivery.Attempt++
				delivery.NextRetry = time.Now().Add(d.retryDelay(delivery.Attempt))

				select {
				case d.retryQueue <- delivery:
				default:
					d.logger.Warn("retry queue full, dropping webhook",
						"webhook_id", delivery.Webhook.ID,
					)
				}
			} else {
				// Mark webhook as failing
				if d.store != nil {
					d.store.IncrementFailure(d.ctx, delivery.Webhook.ID)
				}
			}
		} else {
			d.logger.Debug("webhook delivered",
				"webhook_id", delivery.Webhook.ID,
				"webhook_name", delivery.Webhook.Name,
				"event", delivery.Event.Type(),
			)

			if d.store != nil {
				d.store.UpdateLastTriggered(d.ctx, delivery.Webhook.ID)
				d.store.ResetFailure(d.ctx, delivery.Webhook.ID)
			}
		}
	}
}

// retryWorker handles retry scheduling.
func (d *WebhookDispatcher) retryWorker() {
	defer d.wg.Done()

	pending := make([]*WebhookDelivery, 0)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return

		case delivery, ok := <-d.retryQueue:
			if !ok {
				return
			}
			pending = append(pending, delivery)

		case <-ticker.C:
			now := time.Now()
			remaining := make([]*WebhookDelivery, 0, len(pending))

			for _, delivery := range pending {
				if now.After(delivery.NextRetry) {
					select {
					case d.queue <- delivery:
						d.logger.Debug("webhook retry scheduled",
							"webhook_id", delivery.Webhook.ID,
							"attempt", delivery.Attempt,
						)
					default:
						remaining = append(remaining, delivery)
					}
				} else {
					remaining = append(remaining, delivery)
				}
			}

			pending = remaining
		}
	}
}

// deliver sends a webhook request.
func (d *WebhookDispatcher) deliver(ctx context.Context, delivery *WebhookDelivery) error {
	payload, err := json.Marshal(map[string]any{
		"event":     delivery.Event.Type(),
		"timestamp": delivery.Event.Timestamp(),
		"data":      delivery.Event.Payload(),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.Webhook.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ESP-Webhook/1.0")
	req.Header.Set("X-ESP-Event", delivery.Event.Type())
	req.Header.Set("X-ESP-Delivery", uuid.NewString())
	req.Header.Set("X-ESP-Timestamp", delivery.Event.Timestamp().Format(time.RFC3339))

	// Sign payload if secret is configured
	if delivery.Webhook.Secret != "" {
		signature := d.sign(payload, delivery.Webhook.Secret)
		req.Header.Set("X-ESP-Signature", signature)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sign creates an HMAC signature for the payload.
func (d *WebhookDispatcher) sign(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// retryDelay returns the delay before the next retry attempt.
func (d *WebhookDispatcher) retryDelay(attempt int) time.Duration {
	delays := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
		4 * time.Hour,
	}
	if attempt > len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt-1]
}

// MemoryWebhookStore is an in-memory webhook store for testing.
type MemoryWebhookStore struct {
	webhooks map[uuid.UUID]*Webhook
	mu       sync.RWMutex
}

// NewMemoryWebhookStore creates a new in-memory webhook store.
func NewMemoryWebhookStore() *MemoryWebhookStore {
	return &MemoryWebhookStore{
		webhooks: make(map[uuid.UUID]*Webhook),
	}
}

// Add adds a webhook to the store.
func (s *MemoryWebhookStore) Add(webhook *Webhook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[webhook.ID] = webhook
}

// FindByEvent returns webhooks subscribed to an event type.
func (s *MemoryWebhookStore) FindByEvent(ctx context.Context, eventType string) ([]*Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Webhook
	for _, w := range s.webhooks {
		for _, e := range w.Events {
			if e == eventType || e == "*" {
				result = append(result, w)
				break
			}
		}
	}
	return result, nil
}

// UpdateLastTriggered updates the last triggered timestamp.
func (s *MemoryWebhookStore) UpdateLastTriggered(ctx context.Context, webhookID uuid.UUID) error {
	return nil
}

// IncrementFailure increments the failure count.
func (s *MemoryWebhookStore) IncrementFailure(ctx context.Context, webhookID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.webhooks[webhookID]; ok {
		w.FailureCount++
	}
	return nil
}

// ResetFailure resets the failure count.
func (s *MemoryWebhookStore) ResetFailure(ctx context.Context, webhookID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.webhooks[webhookID]; ok {
		w.FailureCount = 0
	}
	return nil
}
