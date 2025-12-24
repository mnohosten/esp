package filter

import (
	"context"
	"net"
)

// Filter processes messages and returns a result.
type Filter interface {
	// Name returns the filter name.
	Name() string

	// Priority returns execution order (lower = earlier).
	Priority() int

	// Process processes a message.
	Process(ctx context.Context, msg *Message) (*Result, error)
}

// Message represents a message being filtered.
type Message struct {
	ID         string
	From       string
	To         []string
	Subject    string
	Headers    map[string][]string
	Body       []byte
	Size       int64
	ClientIP   net.IP
	ClientHost string
	HELO       string
	AuthUser   string
	Domain     string
}

// Result represents filter processing result.
type Result struct {
	Action       Action
	Score        float64
	Reason       string
	Headers      map[string]string // Headers to add
	Tags         []string          // Tags for categorization
	Metadata     map[string]any    // Additional metadata
	TargetFolder string            // Override delivery folder
}

// Action defines what to do with the message.
type Action int

const (
	// ActionAccept allows the message to proceed.
	ActionAccept Action = iota
	// ActionReject permanently rejects the message.
	ActionReject
	// ActionQuarantine accepts but quarantines the message.
	ActionQuarantine
	// ActionDefer temporarily rejects the message.
	ActionDefer
	// ActionDiscard silently discards the message.
	ActionDiscard
)

// String returns a string representation of the action.
func (a Action) String() string {
	switch a {
	case ActionAccept:
		return "accept"
	case ActionReject:
		return "reject"
	case ActionQuarantine:
		return "quarantine"
	case ActionDefer:
		return "defer"
	case ActionDiscard:
		return "discard"
	default:
		return "unknown"
	}
}

// NewResult creates a new result with Accept action.
func NewResult() *Result {
	return &Result{
		Action:   ActionAccept,
		Headers:  make(map[string]string),
		Tags:     make([]string, 0),
		Metadata: make(map[string]any),
	}
}

// Merge combines another result into this one.
// More severe actions take precedence.
// Scores are accumulated.
// Headers, tags, and metadata are merged.
func (r *Result) Merge(other *Result) {
	if other == nil {
		return
	}

	// More severe action takes precedence
	if other.Action > r.Action {
		r.Action = other.Action
		r.Reason = other.Reason
	}

	// Accumulate scores
	r.Score += other.Score

	// Merge headers
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	for k, v := range other.Headers {
		r.Headers[k] = v
	}

	// Merge tags
	r.Tags = append(r.Tags, other.Tags...)

	// Merge metadata
	if r.Metadata == nil {
		r.Metadata = make(map[string]any)
	}
	for k, v := range other.Metadata {
		r.Metadata[k] = v
	}

	// Target folder from quarantine action
	if other.TargetFolder != "" {
		r.TargetFolder = other.TargetFolder
	}
}
