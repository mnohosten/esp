# Phase 2: SMTP Server Implementation

## Overview

**Goal**: Implement a complete SMTP server supporting inbound mail reception and outbound mail delivery with full TLS support.

**Dependencies**: Phase 1 (Foundation)

**Estimated Complexity**: High

## Prerequisites

- Phase 1 completed
- Understanding of SMTP protocol (RFC 5321)
- Understanding of email authentication (SPF, DKIM, DMARC)

## Deliverables

1. SMTP server accepting connections on ports 25, 465, 587
2. STARTTLS and implicit TLS support
3. Authentication (PLAIN, LOGIN)
4. Multi-domain mail reception
5. SPF/DKIM/DMARC verification
6. Outbound queue with delivery workers
7. Bounce message generation

## Core Components

### 1. SMTP Server Setup

**File**: `internal/smtp/server.go`

```go
// Server wraps the go-smtp server with ESP configuration
type Server struct {
    server    *smtp.Server
    backend   *Backend
    config    config.SMTPConfig
    logger    *slog.Logger
    tlsConfig *tls.Config
}

// New creates a new SMTP server
func New(cfg config.SMTPConfig, backend *Backend, tlsConfig *tls.Config, logger *slog.Logger) *Server

// Start starts all SMTP listeners
func (s *Server) Start(ctx context.Context) error

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error
```

### 2. Backend Implementation

**File**: `internal/smtp/backend.go`

```go
// Backend implements smtp.Backend
type Backend struct {
    domains     *domain.Manager
    users       *user.Store
    queue       *queue.Manager
    filterChain *filter.Chain
    eventBus    *event.Bus
    logger      *slog.Logger
}

// NewSession creates a new SMTP session
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error)
```

### 3. Session Handling

**File**: `internal/smtp/session.go`

```go
// Session implements smtp.Session
type Session struct {
    conn        *smtp.Conn
    backend     *Backend
    domain      *domain.Domain
    user        *user.User
    authenticated bool
    from        string
    recipients  []string
    logger      *slog.Logger
}

// Methods to implement:
// - AuthMechanisms() []string
// - Auth(mech string) (sasl.Server, error)
// - Mail(from string, opts *smtp.MailOptions) error
// - Rcpt(to string, opts *smtp.RcptOptions) error
// - Data(r io.Reader) error
// - Reset()
// - Logout() error
```

### 4. Authentication

**File**: `internal/smtp/auth.go`

```go
// Authenticator handles SMTP authentication
type Authenticator struct {
    users  *user.Store
    logger *slog.Logger
}

// PlainAuth handles PLAIN authentication
func (a *Authenticator) PlainAuth() sasl.Server

// LoginAuth handles LOGIN authentication
func (a *Authenticator) LoginAuth() sasl.Server
```

### 5. SPF/DKIM/DMARC Verification

**File**: `internal/smtp/verify.go`

```go
// Verifier handles email authentication verification
type Verifier struct {
    logger *slog.Logger
}

// VerifySPF checks SPF record for sender
func (v *Verifier) VerifySPF(ctx context.Context, ip net.IP, from string) (SPFResult, error)

// VerifyDKIM checks DKIM signature
func (v *Verifier) VerifyDKIM(ctx context.Context, msg *message.Entity) (DKIMResult, error)

// VerifyDMARC checks DMARC policy
func (v *Verifier) VerifyDMARC(ctx context.Context, from string, spf SPFResult, dkim DKIMResult) (DMARCResult, error)
```

### 6. Outbound Queue

**File**: `internal/queue/manager.go`

```go
// Manager handles the outbound email queue
type Manager struct {
    db       *database.DB
    workers  int
    logger   *slog.Logger
}

// Enqueue adds a message to the queue
func (m *Manager) Enqueue(ctx context.Context, msg *QueuedMessage) error

// Start starts delivery workers
func (m *Manager) Start(ctx context.Context) error

// Stop stops all workers
func (m *Manager) Stop(ctx context.Context) error
```

### 7. Delivery Workers

**File**: `internal/queue/worker.go`

```go
// Worker processes queued messages
type Worker struct {
    id      int
    queue   *Manager
    logger  *slog.Logger
}

// Process attempts to deliver a message
func (w *Worker) Process(ctx context.Context, msg *QueuedMessage) error

// deliverToMX delivers message to remote MX
func (w *Worker) deliverToMX(ctx context.Context, msg *QueuedMessage) error
```

## Task Breakdown

### SMTP Server Core
- [ ] Set up go-smtp server with configuration
- [ ] Implement Backend interface
- [ ] Create Session implementation
- [ ] Add STARTTLS support
- [ ] Add implicit TLS listener (port 465)
- [ ] Configure submission port (587) with required auth

### Authentication
- [ ] Implement PLAIN authentication
- [ ] Implement LOGIN authentication
- [ ] Add auth requirement for submission port
- [ ] Integrate with user store

### Email Verification
- [ ] Implement SPF checking
- [ ] Implement DKIM verification
- [ ] Implement DMARC policy checking
- [ ] Add verification headers to messages

### Message Processing
- [ ] Parse incoming messages with go-message
- [ ] Validate message headers
- [ ] Check message size limits
- [ ] Integrate with filter pipeline

### Local Delivery
- [ ] Validate recipient exists
- [ ] Check domain is local
- [ ] Store message in maildir
- [ ] Update mailbox counters
- [ ] Emit message.received event

### Outbound Queue
- [ ] Create queue manager
- [ ] Implement queue database operations
- [ ] Create delivery worker pool
- [ ] Implement MX resolution
- [ ] Add TLS for outbound connections
- [ ] Implement retry logic with backoff
- [ ] Handle delivery failures

### Bounce Generation
- [ ] Generate bounce messages for failures
- [ ] Handle DSN (Delivery Status Notification)
- [ ] Track bounce rates per domain

### Rate Limiting
- [ ] Per-IP connection limits
- [ ] Per-sender rate limiting
- [ ] Per-recipient rate limiting

## Libraries

```go
import (
    "github.com/emersion/go-smtp"
    "github.com/emersion/go-sasl"
    "github.com/emersion/go-message"
    "github.com/emersion/go-msgauth/dkim"
    "github.com/emersion/go-msgauth/dmarc"
    "blitiri.com.ar/go/spf"
)
```

## Configuration

```yaml
server:
  smtp:
    enabled: true
    listen_addr: ":25"
    submission_addr: ":587"
    implicit_tls_addr: ":465"
    hostname: "mail.example.com"
    max_message_size: 26214400
    max_recipients: 100
    read_timeout: 60s
    write_timeout: 60s
    require_tls: false

    # Rate limiting
    max_connections_per_ip: 10
    max_messages_per_minute: 30

    # Outbound queue
    queue_workers: 4
    retry_intervals:
      - 5m
      - 15m
      - 30m
      - 1h
      - 4h
      - 8h
      - 24h
    max_retries: 7
    bounce_after: 48h
```

## Testing

### Unit Tests
- Backend creation and session handling
- Authentication mechanisms
- SPF/DKIM/DMARC verification
- Queue operations

### Integration Tests
- Full SMTP transaction
- TLS handshake
- Authentication flow
- Local delivery
- Outbound delivery (with mock MX)

### Test Commands
```bash
# Test SMTP connection
swaks --to test@example.com --from sender@other.com --server localhost:25

# Test with STARTTLS
swaks --to test@example.com --from sender@other.com --server localhost:25 --tls

# Test submission with auth
swaks --to test@example.com --from user@example.com --server localhost:587 --auth PLAIN --auth-user user@example.com --auth-password password --tls
```

## Completion Criteria

- [ ] SMTP server accepts connections on all configured ports
- [ ] STARTTLS works correctly
- [ ] Authentication works for submission
- [ ] Local mail delivery stores in maildir
- [ ] SPF/DKIM/DMARC verification adds headers
- [ ] Outbound queue processes and delivers messages
- [ ] Bounces are generated for failures
- [ ] Rate limiting prevents abuse
- [ ] All tests pass

## Next Phase

Once Phase 2 is complete, proceed to [Phase 3: Storage Layer](./phase-03-storage.md).
