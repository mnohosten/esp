# Phase 7: Event System

## Overview

**Goal**: Implement an event-driven architecture with pub/sub, webhooks, and audit logging.

**Dependencies**: Phase 1 (Foundation)

**Estimated Complexity**: Medium

## Prerequisites

- Phase 1 completed
- Understanding of pub/sub patterns
- Understanding of webhook delivery

## Deliverables

1. Event bus implementation
2. Event definitions for all system events
3. Webhook dispatcher with retry logic
4. Audit logging
5. Metrics collection
6. Webhook management API integration

## Core Components

### 1. Event Bus

**File**: `internal/event/bus.go`

```go
// Event is the base interface for all events
type Event interface {
    Type() string
    Timestamp() time.Time
    Payload() any
}

// BaseEvent provides common event functionality
type BaseEvent struct {
    EventType   string    `json:"type"`
    EventTime   time.Time `json:"timestamp"`
    EventData   any       `json:"data"`
}

func (e *BaseEvent) Type() string       { return e.EventType }
func (e *BaseEvent) Timestamp() time.Time { return e.EventTime }
func (e *BaseEvent) Payload() any       { return e.EventData }

// Subscriber handles events
type Subscriber interface {
    ID() string
    Handle(ctx context.Context, event Event) error
}

// Bus is the event bus
type Bus struct {
    subscribers map[string][]Subscriber
    queue       chan Event
    workers     int
    logger      *slog.Logger
    mu          sync.RWMutex
    wg          sync.WaitGroup
    ctx         context.Context
    cancel      context.CancelFunc
}

// New creates a new event bus
func New(workers int, logger *slog.Logger) *Bus {
    ctx, cancel := context.WithCancel(context.Background())
    return &Bus{
        subscribers: make(map[string][]Subscriber),
        queue:       make(chan Event, 1000),
        workers:     workers,
        logger:      logger,
        ctx:         ctx,
        cancel:      cancel,
    }
}

// Subscribe adds a subscriber for an event type
// Use "*" to subscribe to all events
func (b *Bus) Subscribe(eventType string, subscriber Subscriber) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.subscribers[eventType] = append(b.subscribers[eventType], subscriber)
}

// Unsubscribe removes a subscriber
func (b *Bus) Unsubscribe(eventType string, subscriberID string) {
    b.mu.Lock()
    defer b.mu.Unlock()
    subs := b.subscribers[eventType]
    for i, s := range subs {
        if s.ID() == subscriberID {
            b.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
            return
        }
    }
}

// Publish sends an event to the bus
func (b *Bus) Publish(eventType string, data any) {
    event := &BaseEvent{
        EventType: eventType,
        EventTime: time.Now(),
        EventData: data,
    }
    select {
    case b.queue <- event:
    default:
        b.logger.Warn("event queue full, dropping event", "type", eventType)
    }
}

// PublishSync publishes and waits for all handlers
func (b *Bus) PublishSync(ctx context.Context, eventType string, data any) error {
    event := &BaseEvent{
        EventType: eventType,
        EventTime: time.Now(),
        EventData: data,
    }
    return b.dispatch(ctx, event)
}

// Start starts the event bus workers
func (b *Bus) Start() {
    for i := 0; i < b.workers; i++ {
        b.wg.Add(1)
        go b.worker(i)
    }
}

// Stop stops the event bus
func (b *Bus) Stop() {
    b.cancel()
    close(b.queue)
    b.wg.Wait()
}

func (b *Bus) worker(id int) {
    defer b.wg.Done()
    for event := range b.queue {
        if err := b.dispatch(b.ctx, event); err != nil {
            b.logger.Error("event dispatch failed",
                "worker", id,
                "event", event.Type(),
                "error", err,
            )
        }
    }
}

func (b *Bus) dispatch(ctx context.Context, event Event) error {
    b.mu.RLock()
    // Get specific subscribers
    subs := append([]Subscriber{}, b.subscribers[event.Type()]...)
    // Get wildcard subscribers
    subs = append(subs, b.subscribers["*"]...)
    b.mu.RUnlock()

    var errs []error
    for _, sub := range subs {
        if err := sub.Handle(ctx, event); err != nil {
            errs = append(errs, fmt.Errorf("%s: %w", sub.ID(), err))
        }
    }

    if len(errs) > 0 {
        return errors.Join(errs...)
    }
    return nil
}
```

### 2. Event Definitions

**File**: `internal/event/events.go`

```go
// Event type constants
const (
    // Message events
    EventMessageReceived     = "message.received"
    EventMessageSent         = "message.sent"
    EventMessageBounced      = "message.bounced"
    EventMessageDeleted      = "message.deleted"
    EventMessageMoved        = "message.moved"
    EventMessageFlagsChanged = "message.flags_changed"

    // User events
    EventUserLogin       = "user.login"
    EventUserLogout      = "user.logout"
    EventUserCreated     = "user.created"
    EventUserUpdated     = "user.updated"
    EventUserDeleted     = "user.deleted"
    EventUserQuotaWarning = "user.quota_warning"

    // Mailbox events
    EventMailboxCreated  = "mailbox.created"
    EventMailboxDeleted  = "mailbox.deleted"
    EventMailboxRenamed  = "mailbox.renamed"

    // Domain events
    EventDomainCreated   = "domain.created"
    EventDomainUpdated   = "domain.updated"
    EventDomainDeleted   = "domain.deleted"

    // Filter events
    EventFilterMatched   = "filter.matched"
    EventSpamDetected    = "spam.detected"
    EventVirusDetected   = "virus.detected"

    // System events
    EventCertificateRenewed  = "certificate.renewed"
    EventCertificateExpiring = "certificate.expiring"
    EventQueueStuck          = "queue.stuck"
    EventDeliveryFailed      = "delivery.failed"
    EventServerStarted       = "server.started"
    EventServerStopped       = "server.stopped"
)

// MessageReceivedEvent data
type MessageReceivedEvent struct {
    MessageID     string            `json:"message_id"`
    From          string            `json:"from"`
    To            []string          `json:"to"`
    Subject       string            `json:"subject"`
    Size          int64             `json:"size"`
    Domain        string            `json:"domain"`
    User          string            `json:"user"`
    Mailbox       string            `json:"mailbox"`
    SpamScore     float64           `json:"spam_score,omitempty"`
    IsSpam        bool              `json:"is_spam"`
    FilterResults map[string]any    `json:"filter_results,omitempty"`
}

// MessageSentEvent data
type MessageSentEvent struct {
    MessageID   string   `json:"message_id"`
    From        string   `json:"from"`
    To          []string `json:"to"`
    Subject     string   `json:"subject"`
    Size        int64    `json:"size"`
    QueueID     string   `json:"queue_id"`
    Destination string   `json:"destination"`
}

// MessageBouncedEvent data
type MessageBouncedEvent struct {
    MessageID   string `json:"message_id"`
    From        string `json:"from"`
    To          string `json:"to"`
    QueueID     string `json:"queue_id"`
    Error       string `json:"error"`
    Attempts    int    `json:"attempts"`
    Permanent   bool   `json:"permanent"`
}

// UserLoginEvent data
type UserLoginEvent struct {
    UserID    uuid.UUID `json:"user_id"`
    Email     string    `json:"email"`
    IP        string    `json:"ip"`
    UserAgent string    `json:"user_agent"`
    Protocol  string    `json:"protocol"` // imap, smtp, api
    Success   bool      `json:"success"`
    Error     string    `json:"error,omitempty"`
}

// FilterMatchedEvent data
type FilterMatchedEvent struct {
    Filter    string   `json:"filter"`
    MessageID string   `json:"message_id"`
    Action    string   `json:"action"`
    Score     float64  `json:"score"`
    Tags      []string `json:"tags"`
    Reason    string   `json:"reason,omitempty"`
}

// CertificateEvent data
type CertificateEvent struct {
    Domain    string    `json:"domain"`
    ExpiresAt time.Time `json:"expires_at"`
    Issuer    string    `json:"issuer"`
    RenewedAt time.Time `json:"renewed_at,omitempty"`
}
```

### 3. Webhook Dispatcher

**File**: `internal/event/webhook.go`

```go
// WebhookDispatcher sends events to configured webhooks
type WebhookDispatcher struct {
    id         string
    store      WebhookStore
    httpClient *http.Client
    queue      chan *WebhookDelivery
    retryQueue chan *WebhookDelivery
    logger     *slog.Logger
    wg         sync.WaitGroup
}

// WebhookStore interface for webhook persistence
type WebhookStore interface {
    FindByEvent(ctx context.Context, eventType string) ([]*Webhook, error)
    UpdateLastTriggered(ctx context.Context, webhookID uuid.UUID) error
    IncrementFailure(ctx context.Context, webhookID uuid.UUID) error
    ResetFailure(ctx context.Context, webhookID uuid.UUID) error
}

// Webhook configuration
type Webhook struct {
    ID           uuid.UUID
    DomainID     *uuid.UUID
    Name         string
    URL          string
    Events       []string
    Secret       string
    Enabled      bool
    FailureCount int
}

// WebhookDelivery represents a pending delivery
type WebhookDelivery struct {
    Webhook   *Webhook
    Event     Event
    Attempt   int
    NextRetry time.Time
}

func NewWebhookDispatcher(store WebhookStore, logger *slog.Logger) *WebhookDispatcher {
    return &WebhookDispatcher{
        id:         "webhook-dispatcher",
        store:      store,
        httpClient: &http.Client{Timeout: 30 * time.Second},
        queue:      make(chan *WebhookDelivery, 1000),
        retryQueue: make(chan *WebhookDelivery, 1000),
        logger:     logger,
    }
}

func (d *WebhookDispatcher) ID() string { return d.id }

func (d *WebhookDispatcher) Handle(ctx context.Context, event Event) error {
    webhooks, err := d.store.FindByEvent(ctx, event.Type())
    if err != nil {
        return fmt.Errorf("failed to find webhooks: %w", err)
    }

    for _, webhook := range webhooks {
        if !webhook.Enabled || webhook.FailureCount >= 10 {
            continue
        }

        d.queue <- &WebhookDelivery{
            Webhook: webhook,
            Event:   event,
            Attempt: 1,
        }
    }

    return nil
}

func (d *WebhookDispatcher) Start(ctx context.Context) {
    // Main delivery workers
    for i := 0; i < 5; i++ {
        d.wg.Add(1)
        go d.deliveryWorker(ctx, i)
    }

    // Retry worker
    d.wg.Add(1)
    go d.retryWorker(ctx)
}

func (d *WebhookDispatcher) Stop() {
    close(d.queue)
    close(d.retryQueue)
    d.wg.Wait()
}

func (d *WebhookDispatcher) deliveryWorker(ctx context.Context, id int) {
    defer d.wg.Done()

    for delivery := range d.queue {
        if err := d.deliver(ctx, delivery); err != nil {
            d.logger.Error("webhook delivery failed",
                "webhook", delivery.Webhook.ID,
                "attempt", delivery.Attempt,
                "error", err,
            )

            // Schedule retry
            if delivery.Attempt < 5 {
                delivery.Attempt++
                delivery.NextRetry = time.Now().Add(d.retryDelay(delivery.Attempt))
                d.retryQueue <- delivery
            } else {
                // Mark webhook as failing
                d.store.IncrementFailure(ctx, delivery.Webhook.ID)
            }
        } else {
            d.store.UpdateLastTriggered(ctx, delivery.Webhook.ID)
            d.store.ResetFailure(ctx, delivery.Webhook.ID)
        }
    }
}

func (d *WebhookDispatcher) deliver(ctx context.Context, delivery *WebhookDelivery) error {
    payload, err := json.Marshal(map[string]any{
        "event":     delivery.Event.Type(),
        "timestamp": delivery.Event.Timestamp(),
        "data":      delivery.Event.Payload(),
    })
    if err != nil {
        return fmt.Errorf("failed to marshal payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", delivery.Webhook.URL, bytes.NewReader(payload))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "ESP-Webhook/1.0")
    req.Header.Set("X-ESP-Event", delivery.Event.Type())
    req.Header.Set("X-ESP-Delivery", uuid.NewString())

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

func (d *WebhookDispatcher) sign(payload []byte, secret string) string {
    h := hmac.New(sha256.New, []byte(secret))
    h.Write(payload)
    return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

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
```

### 4. Audit Logger

**File**: `internal/event/audit.go`

```go
// AuditLogger logs all events for audit trail
type AuditLogger struct {
    id     string
    db     *database.DB
    logger *slog.Logger
}

func NewAuditLogger(db *database.DB, logger *slog.Logger) *AuditLogger {
    return &AuditLogger{
        id:     "audit-logger",
        db:     db,
        logger: logger,
    }
}

func (a *AuditLogger) ID() string { return a.id }

func (a *AuditLogger) Handle(ctx context.Context, event Event) error {
    // Extract actor info from context if available
    var actorID *uuid.UUID
    var actorIP string
    if claims, ok := ctx.Value("claims").(*api.Claims); ok {
        actorID = &claims.UserID
    }
    if ip, ok := ctx.Value("client_ip").(string); ok {
        actorIP = ip
    }

    // Determine resource type and ID from event data
    resourceType, resourceID := a.extractResource(event)

    details, _ := json.Marshal(event.Payload())

    _, err := a.db.Pool.Exec(ctx, `
        INSERT INTO audit_log (event_type, actor_id, actor_ip, resource_type, resource_id, details, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, event.Type(), actorID, actorIP, resourceType, resourceID, details, event.Timestamp())

    if err != nil {
        return fmt.Errorf("failed to log audit event: %w", err)
    }

    return nil
}

func (a *AuditLogger) extractResource(event Event) (string, *uuid.UUID) {
    switch data := event.Payload().(type) {
    case MessageReceivedEvent:
        return "message", nil
    case UserLoginEvent:
        return "user", &data.UserID
    // ... handle other event types
    default:
        return "", nil
    }
}
```

### 5. Metrics Collector

**File**: `internal/event/metrics.go`

```go
// MetricsCollector collects metrics from events
type MetricsCollector struct {
    id     string
    counters map[string]*prometheus.CounterVec
    gauges   map[string]*prometheus.GaugeVec
    logger   *slog.Logger
}

func NewMetricsCollector(logger *slog.Logger) *MetricsCollector {
    mc := &MetricsCollector{
        id:       "metrics-collector",
        counters: make(map[string]*prometheus.CounterVec),
        gauges:   make(map[string]*prometheus.GaugeVec),
        logger:   logger,
    }

    // Register metrics
    mc.counters["messages_received"] = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "esp_messages_received_total",
            Help: "Total messages received",
        },
        []string{"domain", "spam"},
    )

    mc.counters["messages_sent"] = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "esp_messages_sent_total",
            Help: "Total messages sent",
        },
        []string{"domain"},
    )

    mc.counters["messages_bounced"] = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "esp_messages_bounced_total",
            Help: "Total messages bounced",
        },
        []string{"domain", "permanent"},
    )

    mc.counters["user_logins"] = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "esp_user_logins_total",
            Help: "Total user logins",
        },
        []string{"protocol", "success"},
    )

    return mc
}

func (m *MetricsCollector) ID() string { return m.id }

func (m *MetricsCollector) Handle(ctx context.Context, event Event) error {
    switch data := event.Payload().(type) {
    case MessageReceivedEvent:
        spam := "false"
        if data.IsSpam {
            spam = "true"
        }
        m.counters["messages_received"].WithLabelValues(data.Domain, spam).Inc()

    case MessageSentEvent:
        m.counters["messages_sent"].WithLabelValues(extractDomain(data.From)).Inc()

    case MessageBouncedEvent:
        perm := "false"
        if data.Permanent {
            perm = "true"
        }
        m.counters["messages_bounced"].WithLabelValues(extractDomain(data.From), perm).Inc()

    case UserLoginEvent:
        success := "false"
        if data.Success {
            success = "true"
        }
        m.counters["user_logins"].WithLabelValues(data.Protocol, success).Inc()
    }

    return nil
}
```

## Task Breakdown

### Event Bus
- [ ] Implement event bus with workers
- [ ] Add subscribe/unsubscribe
- [ ] Implement wildcard subscriptions
- [ ] Add sync and async publish
- [ ] Handle queue overflow

### Event Definitions
- [ ] Define all message events
- [ ] Define all user events
- [ ] Define all mailbox events
- [ ] Define all system events
- [ ] Create event data structures

### Event Publishers
- [ ] Add events to SMTP server
- [ ] Add events to IMAP server
- [ ] Add events to API handlers
- [ ] Add events to filter pipeline
- [ ] Add events to queue

### Webhook Dispatcher
- [ ] Implement webhook delivery
- [ ] Add HMAC signature
- [ ] Implement retry logic
- [ ] Track webhook failures
- [ ] Handle webhook timeouts

### Audit Logging
- [ ] Create audit log table
- [ ] Implement audit subscriber
- [ ] Extract actor info
- [ ] Store event details

### Metrics Collection
- [ ] Define Prometheus metrics
- [ ] Implement metrics subscriber
- [ ] Track message counts
- [ ] Track user activity
- [ ] Expose /metrics endpoint

## Configuration

```yaml
events:
  # Event bus settings
  workers: 4
  queue_size: 1000

  # Audit logging
  audit:
    enabled: true
    retention_days: 90

  # Webhook settings
  webhooks:
    enabled: true
    timeout: 30s
    max_retries: 5
    retry_delays:
      - 1m
      - 5m
      - 15m
      - 1h
      - 4h
```

## Completion Criteria

- [ ] Event bus processes events
- [ ] All system events defined
- [ ] Events published from all components
- [ ] Webhooks delivered reliably
- [ ] Audit logging captures all events
- [ ] Prometheus metrics exposed
- [ ] All tests pass

## Next Phase

Once Phase 7 is complete, proceed to [Phase 8: Certificate Management](./phase-08-certificates.md).
