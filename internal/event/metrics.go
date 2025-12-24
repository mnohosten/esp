package event

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a simple atomic counter.
type Counter struct {
	value int64
}

// Inc increments the counter.
func (c *Counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

// Add adds a value to the counter.
func (c *Counter) Add(v int64) {
	atomic.AddInt64(&c.value, v)
}

// Value returns the current value.
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

// Gauge is a simple atomic gauge.
type Gauge struct {
	value int64
}

// Set sets the gauge value.
func (g *Gauge) Set(v int64) {
	atomic.StoreInt64(&g.value, v)
}

// Inc increments the gauge.
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec decrements the gauge.
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Value returns the current value.
func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

// LabeledCounter is a counter with labels.
type LabeledCounter struct {
	counters map[string]*Counter
	mu       sync.RWMutex
}

// NewLabeledCounter creates a new labeled counter.
func NewLabeledCounter() *LabeledCounter {
	return &LabeledCounter{
		counters: make(map[string]*Counter),
	}
}

// WithLabels returns the counter for the given labels.
func (c *LabeledCounter) WithLabels(labels ...string) *Counter {
	key := strings.Join(labels, ":")

	c.mu.RLock()
	if counter, ok := c.counters[key]; ok {
		c.mu.RUnlock()
		return counter
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if counter, ok := c.counters[key]; ok {
		return counter
	}

	counter := &Counter{}
	c.counters[key] = counter
	return counter
}

// All returns all label combinations and their values.
func (c *LabeledCounter) All() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range c.counters {
		result[k] = v.Value()
	}
	return result
}

// Metrics holds all application metrics.
type Metrics struct {
	// Message counters
	MessagesReceived *LabeledCounter // labels: domain, spam
	MessagesSent     *LabeledCounter // labels: domain
	MessagesBounced  *LabeledCounter // labels: domain, permanent
	MessagesDeleted  *Counter

	// User counters
	UserLogins  *LabeledCounter // labels: protocol, success
	UserLogouts *Counter

	// Connection gauges
	SMTPConnections *Gauge
	IMAPConnections *Gauge
	APIConnections  *Gauge

	// Queue gauges
	QueuePending  *Gauge
	QueueDeferred *Gauge

	// Filter counters
	FilterMatches *LabeledCounter // labels: filter, action
	SpamDetected  *Counter
	VirusDetected *Counter

	// System counters
	WebhooksDelivered *Counter
	WebhooksFailed    *Counter
	EventsProcessed   *Counter
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		MessagesReceived:  NewLabeledCounter(),
		MessagesSent:      NewLabeledCounter(),
		MessagesBounced:   NewLabeledCounter(),
		MessagesDeleted:   &Counter{},
		UserLogins:        NewLabeledCounter(),
		UserLogouts:       &Counter{},
		SMTPConnections:   &Gauge{},
		IMAPConnections:   &Gauge{},
		APIConnections:    &Gauge{},
		QueuePending:      &Gauge{},
		QueueDeferred:     &Gauge{},
		FilterMatches:     NewLabeledCounter(),
		SpamDetected:      &Counter{},
		VirusDetected:     &Counter{},
		WebhooksDelivered: &Counter{},
		WebhooksFailed:    &Counter{},
		EventsProcessed:   &Counter{},
	}
}

// MetricsCollector collects metrics from events.
type MetricsCollector struct {
	id      string
	metrics *Metrics
	logger  *slog.Logger
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector(metrics *Metrics, logger *slog.Logger) *MetricsCollector {
	if metrics == nil {
		metrics = NewMetrics()
	}
	return &MetricsCollector{
		id:      "metrics-collector",
		metrics: metrics,
		logger:  logger,
	}
}

// ID returns the subscriber ID.
func (m *MetricsCollector) ID() string { return m.id }

// Handle processes an event and updates metrics.
func (m *MetricsCollector) Handle(ctx context.Context, event Event) error {
	m.metrics.EventsProcessed.Inc()

	switch data := event.Payload().(type) {
	case MessageReceivedEvent:
		spam := "false"
		if data.IsSpam {
			spam = "true"
		}
		m.metrics.MessagesReceived.WithLabels(data.Domain, spam).Inc()

	case MessageSentEvent:
		domain := extractDomain(data.From)
		m.metrics.MessagesSent.WithLabels(domain).Inc()

	case MessageBouncedEvent:
		domain := extractDomain(data.From)
		perm := "false"
		if data.Permanent {
			perm = "true"
		}
		m.metrics.MessagesBounced.WithLabels(domain, perm).Inc()

	case MessageDeletedEvent:
		m.metrics.MessagesDeleted.Inc()

	case UserLoginEvent:
		success := "false"
		if data.Success {
			success = "true"
		}
		m.metrics.UserLogins.WithLabels(data.Protocol, success).Inc()

	case UserLogoutEvent:
		m.metrics.UserLogouts.Inc()

	case FilterMatchedEvent:
		m.metrics.FilterMatches.WithLabels(data.Filter, data.Action).Inc()

	case SpamDetectedEvent:
		m.metrics.SpamDetected.Inc()

	case VirusDetectedEvent:
		m.metrics.VirusDetected.Inc()
	}

	return nil
}

// Metrics returns the metrics instance.
func (m *MetricsCollector) Metrics() *Metrics {
	return m.metrics
}

// extractDomain extracts the domain from an email address.
func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "unknown"
}

// Snapshot returns a snapshot of all metrics.
type MetricsSnapshot struct {
	MessagesReceived  map[string]int64 `json:"messages_received"`
	MessagesSent      map[string]int64 `json:"messages_sent"`
	MessagesBounced   map[string]int64 `json:"messages_bounced"`
	MessagesDeleted   int64            `json:"messages_deleted"`
	UserLogins        map[string]int64 `json:"user_logins"`
	UserLogouts       int64            `json:"user_logouts"`
	SMTPConnections   int64            `json:"smtp_connections"`
	IMAPConnections   int64            `json:"imap_connections"`
	APIConnections    int64            `json:"api_connections"`
	QueuePending      int64            `json:"queue_pending"`
	QueueDeferred     int64            `json:"queue_deferred"`
	FilterMatches     map[string]int64 `json:"filter_matches"`
	SpamDetected      int64            `json:"spam_detected"`
	VirusDetected     int64            `json:"virus_detected"`
	WebhooksDelivered int64            `json:"webhooks_delivered"`
	WebhooksFailed    int64            `json:"webhooks_failed"`
	EventsProcessed   int64            `json:"events_processed"`
}

// Snapshot returns a snapshot of all metrics.
func (m *Metrics) Snapshot() *MetricsSnapshot {
	return &MetricsSnapshot{
		MessagesReceived:  m.MessagesReceived.All(),
		MessagesSent:      m.MessagesSent.All(),
		MessagesBounced:   m.MessagesBounced.All(),
		MessagesDeleted:   m.MessagesDeleted.Value(),
		UserLogins:        m.UserLogins.All(),
		UserLogouts:       m.UserLogouts.Value(),
		SMTPConnections:   m.SMTPConnections.Value(),
		IMAPConnections:   m.IMAPConnections.Value(),
		APIConnections:    m.APIConnections.Value(),
		QueuePending:      m.QueuePending.Value(),
		QueueDeferred:     m.QueueDeferred.Value(),
		FilterMatches:     m.FilterMatches.All(),
		SpamDetected:      m.SpamDetected.Value(),
		VirusDetected:     m.VirusDetected.Value(),
		WebhooksDelivered: m.WebhooksDelivered.Value(),
		WebhooksFailed:    m.WebhooksFailed.Value(),
		EventsProcessed:   m.EventsProcessed.Value(),
	}
}
