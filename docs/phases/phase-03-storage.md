# Phase 3: Storage Layer

## Overview

**Goal**: Implement robust message storage using Maildir format and PostgreSQL for metadata, with full-text search and quota management.

**Dependencies**: Phase 1 (Foundation), Phase 2 (SMTP - partial)

**Estimated Complexity**: Medium

## Prerequisites

- Phase 1 completed
- Understanding of Maildir format
- Understanding of IMAP mailbox semantics

## Deliverables

1. Maildir storage implementation
2. Message store interface
3. Mailbox operations (CRUD)
4. Message metadata indexing
5. Full-text search
6. Quota tracking and enforcement

## Core Components

### 1. Storage Interface

**File**: `internal/storage/store.go`

```go
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
}

// Message represents a stored email message
type Message struct {
    ID           uuid.UUID
    MailboxID    uuid.UUID
    UID          uint32
    MessageID    string
    InReplyTo    string
    Subject      string
    From         string
    To           []string
    Cc           []string
    Date         time.Time
    Size         int64
    Flags        []string
    InternalDate time.Time
    StoragePath  string
    Headers      map[string][]string
    BodyText     string
}
```

### 2. Maildir Implementation

**File**: `internal/storage/maildir/maildir.go`

```go
// Maildir implements message storage using Maildir format
type Maildir struct {
    basePath string
    db       *database.DB
    logger   *slog.Logger
}

// Structure:
// basePath/
//   domain.com/
//     user/
//       cur/           # Read messages
//       new/           # Unread messages
//       tmp/           # Messages being delivered
//       .Sent/         # Sent folder
//         cur/
//         new/
//         tmp/
//       .Drafts/       # Drafts folder
//       .Trash/        # Trash folder

// New creates a new Maildir store
func New(basePath string, db *database.DB, logger *slog.Logger) (*Maildir, error)

// CreateMailbox creates a new maildir folder
func (m *Maildir) CreateMailbox(ctx context.Context, userID uuid.UUID, name string) error

// Store stores a message in the maildir
func (m *Maildir) Store(ctx context.Context, mailboxID uuid.UUID, msg *Message) (uint32, error)

// generateFilename creates a unique maildir filename
func (m *Maildir) generateFilename() string
```

### 3. Mailbox Manager

**File**: `internal/mailbox/mailbox.go`

```go
// Manager handles mailbox operations
type Manager struct {
    db      *database.DB
    store   storage.MessageStore
    logger  *slog.Logger
}

// Mailbox represents an IMAP mailbox
type Mailbox struct {
    ID           uuid.UUID
    UserID       uuid.UUID
    Name         string
    UIDValidity  uint32
    UIDNext      uint32
    Subscribed   bool
    SpecialUse   string
    MessageCount int
    UnreadCount  int
    RecentCount  int
}

// Create creates a new mailbox
func (m *Manager) Create(ctx context.Context, userID uuid.UUID, name string, specialUse string) (*Mailbox, error)

// Delete deletes a mailbox
func (m *Manager) Delete(ctx context.Context, mailboxID uuid.UUID) error

// Rename renames a mailbox
func (m *Manager) Rename(ctx context.Context, mailboxID uuid.UUID, newName string) error

// List lists mailboxes for a user
func (m *Manager) List(ctx context.Context, userID uuid.UUID, pattern string) ([]*Mailbox, error)

// Get gets a mailbox by ID
func (m *Manager) Get(ctx context.Context, mailboxID uuid.UUID) (*Mailbox, error)

// GetByName gets a mailbox by name
func (m *Manager) GetByName(ctx context.Context, userID uuid.UUID, name string) (*Mailbox, error)

// Subscribe/Unsubscribe
func (m *Manager) Subscribe(ctx context.Context, mailboxID uuid.UUID) error
func (m *Manager) Unsubscribe(ctx context.Context, mailboxID uuid.UUID) error

// UpdateCounts updates message counts
func (m *Manager) UpdateCounts(ctx context.Context, mailboxID uuid.UUID) error
```

### 4. Message Indexer

**File**: `internal/storage/index/index.go`

```go
// Indexer handles message indexing for search
type Indexer struct {
    db     *database.DB
    logger *slog.Logger
}

// Index indexes a message for searching
func (i *Indexer) Index(ctx context.Context, msg *storage.Message) error

// Search performs a full-text search
func (i *Indexer) Search(ctx context.Context, mailboxID uuid.UUID, query string) ([]uint32, error)

// SearchAdvanced performs advanced search with criteria
func (i *Indexer) SearchAdvanced(ctx context.Context, mailboxID uuid.UUID, criteria *SearchCriteria) ([]uint32, error)
```

### 5. Search Criteria

**File**: `internal/storage/search.go`

```go
// SearchCriteria defines search parameters
type SearchCriteria struct {
    // Message attributes
    All         bool
    Answered    bool
    Deleted     bool
    Draft       bool
    Flagged     bool
    New         bool
    Recent      bool
    Seen        bool
    Unanswered  bool
    Undeleted   bool
    Undraft     bool
    Unflagged   bool
    Unseen      bool

    // Date criteria
    Before      *time.Time
    On          *time.Time
    Since       *time.Time
    SentBefore  *time.Time
    SentOn      *time.Time
    SentSince   *time.Time

    // Size criteria
    Larger      int64
    Smaller     int64

    // Header criteria
    Header      map[string]string
    From        string
    To          string
    Cc          string
    Bcc         string
    Subject     string

    // Body criteria
    Body        string
    Text        string

    // UID criteria
    UID         []uint32

    // Logical operators
    Not         *SearchCriteria
    Or          []*SearchCriteria
}
```

### 6. Quota Manager

**File**: `internal/storage/quota.go`

```go
// QuotaManager handles user quota
type QuotaManager struct {
    db     *database.DB
    logger *slog.Logger
}

// Quota represents user quota
type Quota struct {
    UserID     uuid.UUID
    Used       int64
    Limit      int64
    MessageCount int
}

// Get returns current quota usage
func (q *QuotaManager) Get(ctx context.Context, userID uuid.UUID) (*Quota, error)

// Check checks if adding size would exceed quota
func (q *QuotaManager) Check(ctx context.Context, userID uuid.UUID, size int64) error

// Update updates quota after message operation
func (q *QuotaManager) Update(ctx context.Context, userID uuid.UUID, delta int64) error

// Recalculate recalculates quota from scratch
func (q *QuotaManager) Recalculate(ctx context.Context, userID uuid.UUID) error
```

## Task Breakdown

### Maildir Implementation
- [ ] Create Maildir directory structure
- [ ] Implement unique filename generation
- [ ] Implement message storage (write to tmp, move to new/cur)
- [ ] Implement message retrieval
- [ ] Implement message deletion
- [ ] Implement message moving between folders
- [ ] Handle flag encoding in filename

### Mailbox Operations
- [ ] Create mailbox manager
- [ ] Implement CRUD operations
- [ ] Handle special-use mailboxes (Inbox, Sent, Drafts, Trash, Junk)
- [ ] Implement mailbox hierarchy (IMAP namespace)
- [ ] Implement subscription management
- [ ] Maintain UID validity and UID next

### Message Metadata
- [ ] Store metadata in PostgreSQL
- [ ] Parse and store envelope data
- [ ] Extract and store headers
- [ ] Extract body text for search
- [ ] Maintain message flags

### Indexing & Search
- [ ] Implement full-text indexing
- [ ] Implement PostgreSQL FTS queries
- [ ] Support all IMAP search criteria
- [ ] Optimize search performance

### Quota Management
- [ ] Track per-user storage usage
- [ ] Enforce quota limits on delivery
- [ ] Provide quota reporting
- [ ] Handle quota exceeded scenarios

### Default Mailboxes
- [ ] Create default mailboxes on user creation:
  - INBOX
  - Sent
  - Drafts
  - Trash
  - Junk/Spam

## Maildir Format

### Filename Format
```
timestamp.uniqueId.hostname:2,flags
```

**Flags (in filename):**
- `D` - Draft
- `F` - Flagged
- `P` - Passed (forwarded)
- `R` - Replied
- `S` - Seen
- `T` - Trashed

**Example:**
```
1703123456.M123456P12345.mail.example.com:2,RS
```

### Directory Structure
```
/var/mail/esp/
├── example.com/
│   ├── user1/
│   │   ├── cur/
│   │   ├── new/
│   │   ├── tmp/
│   │   ├── .Sent/
│   │   │   ├── cur/
│   │   │   ├── new/
│   │   │   └── tmp/
│   │   ├── .Drafts/
│   │   ├── .Trash/
│   │   └── .Junk/
│   └── user2/
└── other.com/
```

## Database Schema Updates

```sql
-- Add to messages table for better indexing
CREATE INDEX messages_message_id_idx ON messages(message_id);
CREATE INDEX messages_subject_idx ON messages USING GIN (to_tsvector('english', subject));
CREATE INDEX messages_flags_idx ON messages USING GIN (flags);

-- Quota tracking view
CREATE VIEW user_quota AS
SELECT
    u.id as user_id,
    u.quota_bytes as quota_limit,
    COALESCE(SUM(m.size), 0) as quota_used,
    COUNT(m.id) as message_count
FROM users u
LEFT JOIN mailboxes mb ON mb.user_id = u.id
LEFT JOIN messages m ON m.mailbox_id = mb.id
GROUP BY u.id;
```

## Configuration

```yaml
storage:
  maildir:
    base_path: /var/mail/esp
    # Create directories with these permissions
    dir_mode: 0750
    file_mode: 0640

  quota:
    # Default quota for new users
    default_quota: 1073741824  # 1GB
    # Warn at this percentage
    warn_percent: 90
    # Check quota before delivery
    enforce: true
```

## Testing

### Unit Tests
- Maildir filename generation
- Message storage and retrieval
- Flag handling
- Quota calculations

### Integration Tests
- Full message lifecycle
- Mailbox operations
- Search functionality
- Quota enforcement

### Test Setup
```bash
# Create test maildir
mkdir -p /tmp/esp-test/example.com/testuser/{cur,new,tmp}
```

## Completion Criteria

- [ ] Messages store and retrieve from Maildir
- [ ] Metadata indexes in PostgreSQL
- [ ] Full-text search works
- [ ] All IMAP search criteria supported
- [ ] Mailbox CRUD operations work
- [ ] Quota tracking accurate
- [ ] Quota enforcement works
- [ ] All tests pass

## Next Phase

Once Phase 3 is complete, proceed to [Phase 4: IMAP Server](./phase-04-imap.md).
