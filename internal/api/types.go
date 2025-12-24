package api

import (
	"time"

	"github.com/google/uuid"
)

// Response is the standard API response wrapper.
type Response struct {
	Success bool        `json:"success"`
	Data    any         `json:"data,omitempty"`
	Error   *ErrorInfo  `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// ErrorInfo contains error details.
type ErrorInfo struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Meta contains pagination metadata.
type Meta struct {
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// LoginRequest is the request for authentication.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse is the response for successful authentication.
type LoginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      UserResponse `json:"user"`
}

// RefreshRequest is the request for token refresh.
type RefreshRequest struct {
	Token string `json:"token" validate:"required"`
}

// CreateDomainRequest is the request for creating a domain.
type CreateDomainRequest struct {
	Name           string `json:"name" validate:"required,fqdn"`
	MaxMailboxSize int64  `json:"max_mailbox_size"`
	MaxMessageSize int64  `json:"max_message_size"`
}

// UpdateDomainRequest is the request for updating a domain.
type UpdateDomainRequest struct {
	Enabled        *bool      `json:"enabled,omitempty"`
	CatchAllUserID *uuid.UUID `json:"catch_all_user_id,omitempty"` // User to receive catch-all emails
	MaxMailboxSize *int64     `json:"max_mailbox_size,omitempty"`
	MaxMessageSize *int64     `json:"max_message_size,omitempty"`
}

// DomainResponse is the response for domain data.
type DomainResponse struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Enabled        bool       `json:"enabled"`
	CatchAllUserID *uuid.UUID `json:"catch_all_user_id,omitempty"` // User receiving catch-all emails
	CatchAllEmail  string     `json:"catch_all_email,omitempty"`   // Email of catch-all user
	DKIMSelector   string     `json:"dkim_selector,omitempty"`
	MaxMailboxSize int64      `json:"max_mailbox_size"`
	MaxMessageSize int64      `json:"max_message_size"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// DNSRecordResponse represents a DNS record for domain setup.
type DNSRecordResponse struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl"`
}

// CreateUserRequest is the request for creating a user.
type CreateUserRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	DisplayName string `json:"display_name"`
	QuotaBytes  int64  `json:"quota_bytes"`
	IsAdmin     bool   `json:"is_admin"`
}

// UpdateUserRequest is the request for updating a user.
type UpdateUserRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	QuotaBytes  *int64  `json:"quota_bytes,omitempty"`
	IsAdmin     *bool   `json:"is_admin,omitempty"`
}

// ChangePasswordRequest is the request for changing a password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// UserResponse is the response for user data.
type UserResponse struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	DomainID    uuid.UUID  `json:"domain_id"`
	Enabled     bool       `json:"enabled"`
	IsAdmin     bool       `json:"is_admin"`
	QuotaBytes  int64      `json:"quota_bytes"`
	UsedBytes   int64      `json:"used_bytes"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
}

// QuotaResponse is the response for quota information.
type QuotaResponse struct {
	QuotaBytes   int64   `json:"quota_bytes"`
	UsedBytes    int64   `json:"used_bytes"`
	UsedPercent  float64 `json:"used_percent"`
	MessageCount int     `json:"message_count"`
}

// MailboxResponse is the response for mailbox data.
type MailboxResponse struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	Name         string    `json:"name"`
	SpecialUse   string    `json:"special_use,omitempty"`
	MessageCount int       `json:"message_count"`
	UnreadCount  int       `json:"unread_count"`
	TotalSize    int64     `json:"total_size"`
	CreatedAt    time.Time `json:"created_at"`
}

// CreateMailboxRequest is the request for creating a mailbox.
type CreateMailboxRequest struct {
	Name       string `json:"name" validate:"required"`
	SpecialUse string `json:"special_use,omitempty"`
}

// MessageResponse is the response for message data.
type MessageResponse struct {
	ID             uuid.UUID `json:"id"`
	UID            uint32    `json:"uid"`
	MessageID      string    `json:"message_id"`
	Subject        string    `json:"subject"`
	From           string    `json:"from"`
	To             []string  `json:"to"`
	Cc             []string  `json:"cc,omitempty"`
	Date           time.Time `json:"date"`
	Size           int64     `json:"size"`
	Flags          []string  `json:"flags"`
	HasAttachments bool      `json:"has_attachments"`
	Preview        string    `json:"preview,omitempty"`
}

// MessageDetailResponse is the detailed response for a message.
type MessageDetailResponse struct {
	MessageResponse
	BodyText string            `json:"body_text,omitempty"`
	BodyHTML string            `json:"body_html,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// UpdateFlagsRequest is the request for updating message flags.
type UpdateFlagsRequest struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
	Set    []string `json:"set,omitempty"`
}

// MoveMessageRequest is the request for moving a message.
type MoveMessageRequest struct {
	MailboxID uuid.UUID `json:"mailbox_id" validate:"required"`
}

// AliasResponse is the response for alias data.
type AliasResponse struct {
	ID          uuid.UUID `json:"id"`
	DomainID    uuid.UUID `json:"domain_id"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateAliasRequest is the request for creating an alias.
type CreateAliasRequest struct {
	Source      string `json:"source" validate:"required"`
	Destination string `json:"destination" validate:"required,email"`
}

// QueueItemResponse is the response for queue item data.
type QueueItemResponse struct {
	ID          uuid.UUID  `json:"id"`
	MessageID   string     `json:"message_id"`
	From        string     `json:"from"`
	To          []string   `json:"to"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	NextAttempt *time.Time `json:"next_attempt,omitempty"`
}

// StatsOverviewResponse is the response for overview statistics.
type StatsOverviewResponse struct {
	Domains        int   `json:"domains"`
	Users          int   `json:"users"`
	Messages       int64 `json:"messages"`
	StorageUsed    int64 `json:"storage_used"`
	QueueSize      int   `json:"queue_size"`
	MessagesToday  int64 `json:"messages_today"`
	MessagesHour   int64 `json:"messages_hour"`
}

// HealthResponse is the response for health check.
type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Services  map[string]string `json:"services"`
}
