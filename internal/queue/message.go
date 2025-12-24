// Package queue implements the outbound email queue for ESP.
package queue

import (
	"time"
)

// Status represents the status of a queued message.
type Status string

const (
	StatusPending   Status = "pending"
	StatusProcessing Status = "processing"
	StatusDelivered Status = "delivered"
	StatusDeferred  Status = "deferred"
	StatusBounced   Status = "bounced"
	StatusFailed    Status = "failed"
)

// Message represents a queued email message.
type Message struct {
	ID          string    `json:"id"`
	MessageID   string    `json:"message_id"`
	Sender      string    `json:"sender"`
	Recipient   string    `json:"recipient"`
	MessagePath string    `json:"message_path"`
	Size        int64     `json:"size"`

	Status      Status    `json:"status"`
	Priority    int       `json:"priority"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error,omitempty"`

	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// DeliveryResult represents the result of a delivery attempt.
type DeliveryResult struct {
	Success     bool
	Permanent   bool   // If true, don't retry
	Error       string
	RemoteHost  string
	RemoteIP    string
	ResponseCode int
	ResponseMsg string
}

// IsRetryable returns true if the message should be retried.
func (r *DeliveryResult) IsRetryable() bool {
	return !r.Success && !r.Permanent
}

// EnqueueOptions provides options when enqueueing a message.
type EnqueueOptions struct {
	Priority    int
	DelayUntil  time.Time
	ExpiresAt   time.Time
}

// DefaultEnqueueOptions returns default enqueue options.
func DefaultEnqueueOptions() EnqueueOptions {
	return EnqueueOptions{
		Priority:   0,
		DelayUntil: time.Now(),
		ExpiresAt:  time.Now().Add(48 * time.Hour), // Default 48h expiry
	}
}
