package event

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID           uuid.UUID  `json:"id"`
	EventType    string     `json:"event_type"`
	ActorID      *uuid.UUID `json:"actor_id,omitempty"`
	ActorIP      string     `json:"actor_ip,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	Details      string     `json:"details"`
	Timestamp    time.Time  `json:"timestamp"`
}

// AuditStore provides audit log persistence.
type AuditStore interface {
	// Insert inserts an audit entry.
	Insert(ctx context.Context, entry *AuditEntry) error

	// Query queries audit entries.
	Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
}

// AuditFilter is used to query audit entries.
type AuditFilter struct {
	EventType    string
	ActorID      *uuid.UUID
	ResourceType string
	ResourceID   *uuid.UUID
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}

// AuditLogger logs all events for audit trail.
type AuditLogger struct {
	id     string
	store  AuditStore
	logger *slog.Logger
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(store AuditStore, logger *slog.Logger) *AuditLogger {
	return &AuditLogger{
		id:     "audit-logger",
		store:  store,
		logger: logger,
	}
}

// ID returns the subscriber ID.
func (a *AuditLogger) ID() string { return a.id }

// Handle logs an event to the audit trail.
func (a *AuditLogger) Handle(ctx context.Context, event Event) error {
	if a.store == nil {
		return nil
	}

	// Extract actor info from context
	var actorID *uuid.UUID
	var actorIP string

	if id, ok := ctx.Value("actor_id").(uuid.UUID); ok {
		actorID = &id
	}
	if ip, ok := ctx.Value("actor_ip").(string); ok {
		actorIP = ip
	}

	// Determine resource type and ID from event data
	resourceType, resourceID := extractResource(event)

	// Serialize event details
	details, err := json.Marshal(event.Payload())
	if err != nil {
		details = []byte("{}")
	}

	entry := &AuditEntry{
		ID:           uuid.New(),
		EventType:    event.Type(),
		ActorID:      actorID,
		ActorIP:      actorIP,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      string(details),
		Timestamp:    event.Timestamp(),
	}

	if err := a.store.Insert(ctx, entry); err != nil {
		a.logger.Error("failed to insert audit entry",
			"event_type", event.Type(),
			"error", err,
		)
		return err
	}

	return nil
}

// extractResource determines resource type and ID from event payload.
func extractResource(event Event) (string, *uuid.UUID) {
	switch data := event.Payload().(type) {
	case MessageReceivedEvent:
		return "message", nil
	case MessageSentEvent:
		return "message", nil
	case MessageDeletedEvent:
		return "message", &data.MailboxID
	case MessageMovedEvent:
		return "message", &data.ToMailboxID
	case UserLoginEvent:
		return "user", &data.UserID
	case UserLogoutEvent:
		return "user", &data.UserID
	case UserCreatedEvent:
		return "user", &data.UserID
	case UserUpdatedEvent:
		return "user", &data.UserID
	case UserDeletedEvent:
		return "user", &data.UserID
	case MailboxCreatedEvent:
		return "mailbox", &data.MailboxID
	case MailboxDeletedEvent:
		return "mailbox", &data.MailboxID
	case MailboxRenamedEvent:
		return "mailbox", &data.MailboxID
	case DomainCreatedEvent:
		return "domain", &data.DomainID
	case DomainUpdatedEvent:
		return "domain", &data.DomainID
	case DomainDeletedEvent:
		return "domain", &data.DomainID
	default:
		return "", nil
	}
}

// MemoryAuditStore is an in-memory audit store for testing.
type MemoryAuditStore struct {
	entries []*AuditEntry
}

// NewMemoryAuditStore creates a new in-memory audit store.
func NewMemoryAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{
		entries: make([]*AuditEntry, 0),
	}
}

// Insert inserts an audit entry.
func (s *MemoryAuditStore) Insert(ctx context.Context, entry *AuditEntry) error {
	s.entries = append(s.entries, entry)
	return nil
}

// Query queries audit entries.
func (s *MemoryAuditStore) Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	var result []*AuditEntry

	for _, e := range s.entries {
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		if filter.ActorID != nil && (e.ActorID == nil || *e.ActorID != *filter.ActorID) {
			continue
		}
		if filter.ResourceType != "" && e.ResourceType != filter.ResourceType {
			continue
		}
		if filter.ResourceID != nil && (e.ResourceID == nil || *e.ResourceID != *filter.ResourceID) {
			continue
		}
		if filter.Since != nil && e.Timestamp.Before(*filter.Since) {
			continue
		}
		if filter.Until != nil && e.Timestamp.After(*filter.Until) {
			continue
		}

		result = append(result, e)
	}

	// Apply pagination
	start := filter.Offset
	if start > len(result) {
		return []*AuditEntry{}, nil
	}

	end := start + filter.Limit
	if filter.Limit == 0 || end > len(result) {
		end = len(result)
	}

	return result[start:end], nil
}

// Entries returns all entries for testing.
func (s *MemoryAuditStore) Entries() []*AuditEntry {
	return s.entries
}

// SQLAuditStore is a SQL-based audit store.
type SQLAuditStore struct {
	db *sql.DB
}

// NewSQLAuditStore creates a new SQL audit store.
func NewSQLAuditStore(db *sql.DB) *SQLAuditStore {
	return &SQLAuditStore{db: db}
}

// Insert inserts an audit entry.
func (s *SQLAuditStore) Insert(ctx context.Context, entry *AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (id, event_type, actor_id, actor_ip, resource_type, resource_id, details, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, entry.ID, entry.EventType, entry.ActorID, entry.ActorIP, entry.ResourceType, entry.ResourceID, entry.Details, entry.Timestamp)
	return err
}

// Query queries audit entries.
func (s *SQLAuditStore) Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	query := `SELECT id, event_type, actor_id, actor_ip, resource_type, resource_id, details, timestamp
			  FROM audit_log WHERE 1=1`
	args := make([]any, 0)
	argNum := 1

	if filter.EventType != "" {
		query += ` AND event_type = $` + string(rune('0'+argNum))
		args = append(args, filter.EventType)
		argNum++
	}

	if filter.Since != nil {
		query += ` AND timestamp >= $` + string(rune('0'+argNum))
		args = append(args, filter.Since)
		argNum++
	}

	if filter.Until != nil {
		query += ` AND timestamp <= $` + string(rune('0'+argNum))
		args = append(args, filter.Until)
		argNum++
	}

	query += ` ORDER BY timestamp DESC`

	if filter.Limit > 0 {
		query += ` LIMIT $` + string(rune('0'+argNum))
		args = append(args, filter.Limit)
		argNum++
	}

	if filter.Offset > 0 {
		query += ` OFFSET $` + string(rune('0'+argNum))
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.EventType, &e.ActorID, &e.ActorIP, &e.ResourceType, &e.ResourceID, &e.Details, &e.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}

	return entries, rows.Err()
}
