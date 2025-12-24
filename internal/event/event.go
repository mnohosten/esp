package event

import (
	"time"

	"github.com/google/uuid"
)

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
	EventUserLogin        = "user.login"
	EventUserLogout       = "user.logout"
	EventUserCreated      = "user.created"
	EventUserUpdated      = "user.updated"
	EventUserDeleted      = "user.deleted"
	EventUserQuotaWarning = "user.quota_warning"

	// Mailbox events
	EventMailboxCreated = "mailbox.created"
	EventMailboxDeleted = "mailbox.deleted"
	EventMailboxRenamed = "mailbox.renamed"

	// Domain events
	EventDomainCreated = "domain.created"
	EventDomainUpdated = "domain.updated"
	EventDomainDeleted = "domain.deleted"

	// Filter events
	EventFilterMatched = "filter.matched"
	EventFilterError   = "filter.error"
	EventSpamDetected  = "spam.detected"
	EventVirusDetected = "virus.detected"

	// System events
	EventCertificateRenewed  = "certificate.renewed"
	EventCertificateExpiring = "certificate.expiring"
	EventQueueStuck          = "queue.stuck"
	EventDeliveryFailed      = "delivery.failed"
	EventServerStarted       = "server.started"
	EventServerStopped       = "server.stopped"
)

// Event is the base interface for all events.
type Event interface {
	Type() string
	Timestamp() time.Time
	Payload() any
}

// BaseEvent provides common event functionality.
type BaseEvent struct {
	EventType string    `json:"type"`
	EventTime time.Time `json:"timestamp"`
	EventData any       `json:"data"`
}

// Type returns the event type.
func (e *BaseEvent) Type() string { return e.EventType }

// Timestamp returns the event timestamp.
func (e *BaseEvent) Timestamp() time.Time { return e.EventTime }

// Payload returns the event data.
func (e *BaseEvent) Payload() any { return e.EventData }

// NewEvent creates a new event.
func NewEvent(eventType string, data any) *BaseEvent {
	return &BaseEvent{
		EventType: eventType,
		EventTime: time.Now(),
		EventData: data,
	}
}

// MessageReceivedEvent is emitted when a message is received.
type MessageReceivedEvent struct {
	MessageID     string         `json:"message_id"`
	From          string         `json:"from"`
	To            []string       `json:"to"`
	Subject       string         `json:"subject"`
	Size          int64          `json:"size"`
	Domain        string         `json:"domain"`
	User          string         `json:"user"`
	Mailbox       string         `json:"mailbox"`
	SpamScore     float64        `json:"spam_score,omitempty"`
	IsSpam        bool           `json:"is_spam"`
	FilterResults map[string]any `json:"filter_results,omitempty"`
}

// MessageSentEvent is emitted when a message is sent.
type MessageSentEvent struct {
	MessageID   string   `json:"message_id"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	Size        int64    `json:"size"`
	QueueID     string   `json:"queue_id"`
	Destination string   `json:"destination"`
}

// MessageBouncedEvent is emitted when a message bounces.
type MessageBouncedEvent struct {
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	QueueID   string `json:"queue_id"`
	Error     string `json:"error"`
	Attempts  int    `json:"attempts"`
	Permanent bool   `json:"permanent"`
}

// MessageDeletedEvent is emitted when a message is deleted.
type MessageDeletedEvent struct {
	MessageID string    `json:"message_id"`
	MailboxID uuid.UUID `json:"mailbox_id"`
	UserID    uuid.UUID `json:"user_id"`
	UID       uint32    `json:"uid"`
}

// MessageMovedEvent is emitted when a message is moved.
type MessageMovedEvent struct {
	MessageID     string    `json:"message_id"`
	FromMailboxID uuid.UUID `json:"from_mailbox_id"`
	ToMailboxID   uuid.UUID `json:"to_mailbox_id"`
	UserID        uuid.UUID `json:"user_id"`
	UID           uint32    `json:"uid"`
	NewUID        uint32    `json:"new_uid"`
}

// MessageFlagsChangedEvent is emitted when message flags change.
type MessageFlagsChangedEvent struct {
	MessageID string    `json:"message_id"`
	MailboxID uuid.UUID `json:"mailbox_id"`
	UID       uint32    `json:"uid"`
	OldFlags  []string  `json:"old_flags"`
	NewFlags  []string  `json:"new_flags"`
}

// UserLoginEvent is emitted on user login.
type UserLoginEvent struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Protocol  string    `json:"protocol"` // imap, smtp, api
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// UserLogoutEvent is emitted on user logout.
type UserLogoutEvent struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Protocol string    `json:"protocol"`
}

// UserCreatedEvent is emitted when a user is created.
type UserCreatedEvent struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	DomainID uuid.UUID `json:"domain_id"`
	IsAdmin  bool      `json:"is_admin"`
}

// UserUpdatedEvent is emitted when a user is updated.
type UserUpdatedEvent struct {
	UserID  uuid.UUID      `json:"user_id"`
	Email   string         `json:"email"`
	Changes map[string]any `json:"changes"`
}

// UserDeletedEvent is emitted when a user is deleted.
type UserDeletedEvent struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	DomainID uuid.UUID `json:"domain_id"`
}

// UserQuotaWarningEvent is emitted when user approaches quota.
type UserQuotaWarningEvent struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	UsedBytes   int64     `json:"used_bytes"`
	QuotaBytes  int64     `json:"quota_bytes"`
	UsedPercent float64   `json:"used_percent"`
}

// MailboxCreatedEvent is emitted when a mailbox is created.
type MailboxCreatedEvent struct {
	MailboxID  uuid.UUID `json:"mailbox_id"`
	UserID     uuid.UUID `json:"user_id"`
	Name       string    `json:"name"`
	SpecialUse string    `json:"special_use,omitempty"`
}

// MailboxDeletedEvent is emitted when a mailbox is deleted.
type MailboxDeletedEvent struct {
	MailboxID uuid.UUID `json:"mailbox_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
}

// MailboxRenamedEvent is emitted when a mailbox is renamed.
type MailboxRenamedEvent struct {
	MailboxID uuid.UUID `json:"mailbox_id"`
	UserID    uuid.UUID `json:"user_id"`
	OldName   string    `json:"old_name"`
	NewName   string    `json:"new_name"`
}

// DomainCreatedEvent is emitted when a domain is created.
type DomainCreatedEvent struct {
	DomainID uuid.UUID `json:"domain_id"`
	Name     string    `json:"name"`
}

// DomainUpdatedEvent is emitted when a domain is updated.
type DomainUpdatedEvent struct {
	DomainID uuid.UUID      `json:"domain_id"`
	Name     string         `json:"name"`
	Changes  map[string]any `json:"changes"`
}

// DomainDeletedEvent is emitted when a domain is deleted.
type DomainDeletedEvent struct {
	DomainID uuid.UUID `json:"domain_id"`
	Name     string    `json:"name"`
}

// FilterMatchedEvent is emitted when a filter matches.
type FilterMatchedEvent struct {
	Filter    string   `json:"filter"`
	MessageID string   `json:"message_id"`
	Action    string   `json:"action"`
	Score     float64  `json:"score"`
	Tags      []string `json:"tags"`
	Reason    string   `json:"reason,omitempty"`
}

// FilterErrorEvent is emitted when a filter errors.
type FilterErrorEvent struct {
	Filter    string `json:"filter"`
	MessageID string `json:"message_id"`
	Error     string `json:"error"`
}

// SpamDetectedEvent is emitted when spam is detected.
type SpamDetectedEvent struct {
	MessageID string   `json:"message_id"`
	From      string   `json:"from"`
	Score     float64  `json:"score"`
	Symbols   []string `json:"symbols"`
	Action    string   `json:"action"`
}

// VirusDetectedEvent is emitted when a virus is detected.
type VirusDetectedEvent struct {
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	Virus     string `json:"virus"`
}

// CertificateRenewedEvent is emitted when a certificate is renewed.
type CertificateRenewedEvent struct {
	Domain    string    `json:"domain"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer"`
	RenewedAt time.Time `json:"renewed_at"`
}

// CertificateExpiringEvent is emitted when a certificate is expiring.
type CertificateExpiringEvent struct {
	Domain     string    `json:"domain"`
	ExpiresAt  time.Time `json:"expires_at"`
	DaysLeft   int       `json:"days_left"`
}

// QueueStuckEvent is emitted when the queue is stuck.
type QueueStuckEvent struct {
	QueueID     string    `json:"queue_id"`
	MessageID   string    `json:"message_id"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	LastError   string    `json:"last_error"`
}

// DeliveryFailedEvent is emitted when delivery fails permanently.
type DeliveryFailedEvent struct {
	QueueID   string `json:"queue_id"`
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Error     string `json:"error"`
	Attempts  int    `json:"attempts"`
}

// ServerStartedEvent is emitted when a server starts.
type ServerStartedEvent struct {
	Server  string `json:"server"`
	Address string `json:"address"`
	Version string `json:"version"`
}

// ServerStoppedEvent is emitted when a server stops.
type ServerStoppedEvent struct {
	Server string `json:"server"`
	Reason string `json:"reason,omitempty"`
}
