package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MessageStore defines the interface for message storage
type MessageStore interface {
	// Message operations
	Store(ctx context.Context, mailboxID uuid.UUID, msg *Message) (uint32, error)
	Get(ctx context.Context, mailboxID uuid.UUID, uid uint32) (*Message, error)
	GetByRange(ctx context.Context, mailboxID uuid.UUID, start, end uint32) ([]*Message, error)
	Delete(ctx context.Context, mailboxID uuid.UUID, uids []uint32) error
	Move(ctx context.Context, srcMailbox, dstMailbox uuid.UUID, uids []uint32) error
	Copy(ctx context.Context, srcMailbox, dstMailbox uuid.UUID, uids []uint32) ([]uint32, error)

	// Flag operations
	SetFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error
	AddFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error
	RemoveFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error

	// Search
	Search(ctx context.Context, mailboxID uuid.UUID, criteria *SearchCriteria) ([]uint32, error)

	// Raw message access
	GetRaw(ctx context.Context, mailboxID uuid.UUID, uid uint32) ([]byte, error)
}

// Message represents a stored email message
type Message struct {
	ID           uuid.UUID
	MailboxID    uuid.UUID
	UID          uint32
	MessageID    string
	InReplyTo    string
	References   []string
	Subject      string
	From         string
	To           []string
	Cc           []string
	Bcc          []string
	ReplyTo      string
	Date         time.Time
	Size         int64
	Flags        []string
	InternalDate time.Time
	StoragePath  string
	Headers      map[string][]string
	BodyText     string
	BodyHTML     string
}

// SearchCriteria defines search parameters for IMAP SEARCH
type SearchCriteria struct {
	// Message attributes
	All        bool
	Answered   bool
	Deleted    bool
	Draft      bool
	Flagged    bool
	New        bool
	Recent     bool
	Seen       bool
	Unanswered bool
	Undeleted  bool
	Undraft    bool
	Unflagged  bool
	Unseen     bool

	// Date criteria
	Before     *time.Time
	On         *time.Time
	Since      *time.Time
	SentBefore *time.Time
	SentOn     *time.Time
	SentSince  *time.Time

	// Size criteria
	Larger  int64
	Smaller int64

	// Header criteria
	Header  map[string]string
	From    string
	To      string
	Cc      string
	Bcc     string
	Subject string

	// Body criteria
	Body string
	Text string

	// UID criteria
	UID []uint32

	// Sequence set criteria
	SeqSet []uint32

	// Logical operators
	Not *SearchCriteria
	Or  []*SearchCriteria
}
