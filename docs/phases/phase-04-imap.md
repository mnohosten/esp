# Phase 4: IMAP Server Implementation

## Overview

**Goal**: Implement a complete IMAP4rev1 server with all standard capabilities, IDLE support, and extensions.

**Dependencies**: Phase 1 (Foundation), Phase 3 (Storage)

**Estimated Complexity**: High

## Prerequisites

- Phase 1 and Phase 3 completed
- Understanding of IMAP4rev1 protocol (RFC 3501)
- Understanding of IMAP extensions

## Deliverables

1. IMAP server on ports 143 and 993
2. Full IMAP4rev1 command support
3. STARTTLS and implicit TLS
4. IDLE command for push notifications
5. SORT and SEARCH extensions
6. QUOTA extension
7. MOVE extension

## Core Components

### 1. IMAP Server Setup

**File**: `internal/imap/server.go`

```go
// Server wraps the go-imap server
type Server struct {
    server    *imapserver.Server
    backend   *Backend
    config    config.IMAPConfig
    logger    *slog.Logger
    tlsConfig *tls.Config
}

// New creates a new IMAP server
func New(cfg config.IMAPConfig, backend *Backend, tlsConfig *tls.Config, logger *slog.Logger) *Server

// Start starts the IMAP server
func (s *Server) Start(ctx context.Context) error

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error
```

### 2. Backend Implementation

**File**: `internal/imap/backend.go`

```go
// Backend implements imapserver.Backend
type Backend struct {
    db          *database.DB
    users       *user.Store
    mailboxes   *mailbox.Manager
    store       storage.MessageStore
    eventBus    *event.Bus
    logger      *slog.Logger
}

// Login authenticates a user
func (b *Backend) Login(connInfo *imap.ConnInfo, username, password string) (imapserver.Session, error)
```

### 3. Session Implementation

**File**: `internal/imap/session.go`

```go
// Session implements imapserver.Session
type Session struct {
    backend     *Backend
    user        *user.User
    selected    *mailbox.Mailbox
    readonly    bool
    logger      *slog.Logger

    // For IDLE
    idleUpdates chan imapserver.Update
}

// Required interface methods:
func (s *Session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error)
func (s *Session) Create(name string, options *imap.CreateOptions) error
func (s *Session) Delete(name string) error
func (s *Session) Rename(oldName, newName string) error
func (s *Session) Subscribe(name string) error
func (s *Session) Unsubscribe(name string) error
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error
func (s *Session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error)
func (s *Session) Append(name string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error)
func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error
func (s *Session) Close() error
func (s *Session) Logout() error
```

### 4. Mailbox Session

**File**: `internal/imap/mailbox_session.go`

```go
// MailboxSession handles operations on a selected mailbox
type MailboxSession struct {
    session  *Session
    mailbox  *mailbox.Mailbox
    readonly bool
}

// Message operations
func (m *MailboxSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error
func (m *MailboxSession) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error)
func (m *MailboxSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error
func (m *MailboxSession) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error)
func (m *MailboxSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error
func (m *MailboxSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error
```

### 5. FETCH Handler

**File**: `internal/imap/fetch.go`

```go
// FetchHandler handles FETCH command
type FetchHandler struct {
    store  storage.MessageStore
    logger *slog.Logger
}

// Fetch retrieves message data
func (h *FetchHandler) Fetch(ctx context.Context, mailboxID uuid.UUID, seqSet imap.NumSet, items []imap.FetchItem) ([]*FetchResponse, error)

// FetchResponse contains fetched message data
type FetchResponse struct {
    SeqNum      uint32
    UID         uint32
    Flags       []imap.Flag
    Envelope    *imap.Envelope
    BodyStructure *imap.BodyStructure
    Body        map[string][]byte
    InternalDate time.Time
    Size        uint32
}
```

### 6. SEARCH Handler

**File**: `internal/imap/search.go`

```go
// SearchHandler handles SEARCH command
type SearchHandler struct {
    store   storage.MessageStore
    indexer *index.Indexer
    logger  *slog.Logger
}

// Search performs IMAP search
func (h *SearchHandler) Search(ctx context.Context, mailboxID uuid.UUID, criteria *imap.SearchCriteria) (*imap.SearchData, error)

// convertCriteria converts IMAP criteria to storage criteria
func (h *SearchHandler) convertCriteria(criteria *imap.SearchCriteria) *storage.SearchCriteria
```

### 7. IDLE Handler

**File**: `internal/imap/idle.go`

```go
// IdleHandler manages IDLE connections
type IdleHandler struct {
    sessions map[uuid.UUID][]*IdleSession
    eventBus *event.Bus
    mu       sync.RWMutex
    logger   *slog.Logger
}

// IdleSession represents an IDLE connection
type IdleSession struct {
    userID    uuid.UUID
    mailboxID uuid.UUID
    updates   chan<- imapserver.Update
}

// Register registers a session for IDLE updates
func (h *IdleHandler) Register(session *IdleSession)

// Unregister removes a session
func (h *IdleHandler) Unregister(session *IdleSession)

// Notify sends update to relevant sessions
func (h *IdleHandler) Notify(mailboxID uuid.UUID, update imapserver.Update)
```

## IMAP Commands to Implement

### Connection State
- [x] CAPABILITY
- [ ] NOOP
- [ ] LOGOUT

### Not Authenticated State
- [ ] STARTTLS
- [ ] AUTHENTICATE
- [ ] LOGIN

### Authenticated State
- [ ] SELECT
- [ ] EXAMINE
- [ ] CREATE
- [ ] DELETE
- [ ] RENAME
- [ ] SUBSCRIBE
- [ ] UNSUBSCRIBE
- [ ] LIST
- [ ] LSUB
- [ ] STATUS
- [ ] APPEND

### Selected State
- [ ] CHECK
- [ ] CLOSE
- [ ] EXPUNGE
- [ ] SEARCH
- [ ] FETCH
- [ ] STORE
- [ ] COPY
- [ ] UID (prefix for COPY, FETCH, SEARCH, STORE)

### Extensions
- [ ] IDLE (RFC 2177)
- [ ] SORT (RFC 5256)
- [ ] MOVE (RFC 6851)
- [ ] QUOTA (RFC 2087)
- [ ] NAMESPACE (RFC 2342)
- [ ] UIDPLUS (RFC 4315)
- [ ] LITERAL+ (RFC 7888)
- [ ] SASL-IR (RFC 4959)

## Task Breakdown

### Server Setup
- [ ] Set up go-imap v2 server
- [ ] Configure TLS (STARTTLS and implicit)
- [ ] Implement connection handling
- [ ] Add capability announcements

### Authentication
- [ ] Implement LOGIN command
- [ ] Implement AUTHENTICATE PLAIN
- [ ] Add STARTTLS support
- [ ] Integrate with user store

### Mailbox Commands
- [ ] Implement SELECT/EXAMINE
- [ ] Implement CREATE
- [ ] Implement DELETE
- [ ] Implement RENAME
- [ ] Implement SUBSCRIBE/UNSUBSCRIBE
- [ ] Implement LIST/LSUB
- [ ] Implement STATUS
- [ ] Handle special-use attributes

### Message Commands
- [ ] Implement FETCH with all data items
- [ ] Implement SEARCH with all criteria
- [ ] Implement STORE for flag changes
- [ ] Implement COPY
- [ ] Implement EXPUNGE
- [ ] Implement APPEND

### Extensions
- [ ] Implement IDLE
- [ ] Implement SORT
- [ ] Implement MOVE
- [ ] Implement QUOTA
- [ ] Implement NAMESPACE

### IDLE Implementation
- [ ] Subscribe to mailbox events
- [ ] Send EXISTS/RECENT/EXPUNGE updates
- [ ] Handle DONE command
- [ ] Manage connection timeout

## Libraries

```go
import (
    "github.com/emersion/go-imap/v2"
    "github.com/emersion/go-imap/v2/imapserver"
    "github.com/emersion/go-message"
)
```

## Configuration

```yaml
server:
  imap:
    enabled: true
    listen_addr: ":143"
    implicit_tls_addr: ":993"
    read_timeout: 30m
    write_timeout: 60s

    # IDLE settings
    idle_timeout: 30m
    idle_poll_interval: 2m

    # Limits
    max_connections: 1000
    max_connections_per_user: 10

    # Capabilities to advertise
    capabilities:
      - IMAP4rev1
      - STARTTLS
      - AUTH=PLAIN
      - IDLE
      - MOVE
      - QUOTA
      - SORT
      - UIDPLUS
```

## Testing

### Unit Tests
- Session lifecycle
- Command parsing
- Search criteria conversion
- FETCH data items

### Integration Tests
- Full authentication flow
- Mailbox operations
- Message operations
- IDLE notifications

### Test with Client
```bash
# Using openssl
openssl s_client -connect localhost:993

# Or netcat for non-TLS
nc localhost 143

# IMAP commands:
a001 LOGIN user@example.com password
a002 SELECT INBOX
a003 FETCH 1:* (FLAGS ENVELOPE)
a004 LOGOUT
```

### Test with Email Client
- Thunderbird
- Apple Mail
- Outlook
- K-9 Mail (Android)

## Completion Criteria

- [ ] Server accepts connections on 143 and 993
- [ ] TLS/STARTTLS works correctly
- [ ] Authentication works
- [ ] All mailbox commands implemented
- [ ] All message commands implemented
- [ ] IDLE sends real-time updates
- [ ] SORT and SEARCH work correctly
- [ ] QUOTA reports accurate data
- [ ] Standard email clients connect successfully
- [ ] All tests pass

## Next Phase

Once Phase 4 is complete, proceed to [Phase 5: Filter Pipeline](./phase-05-filters.md).
