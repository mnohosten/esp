# ESP Architecture Overview

## System Architecture

```
                                    ┌──────────────────────────────────────┐
                                    │        External Services             │
                                    │  Let's Encrypt │ DNS │ LLM APIs     │
                                    └────────────────┬─────────────────────┘
                                                     │
    ┌────────────────────────────────────────────────┼────────────────────────────────────────────────┐
    │                                    ESP Server  │                                                │
    │  ┌─────────────────────────────────────────────┼─────────────────────────────────────────────┐  │
    │  │                              Ingress Layer  │                                             │  │
    │  │  ┌───────────────┐  ┌───────────────┐  ┌────┴────────┐  ┌───────────────────────────────┐ │  │
    │  │  │  SMTP Server  │  │  IMAP Server  │  │  REST API   │  │    Certificate Manager        │ │  │
    │  │  │  :25 :465 :587│  │  :993 :143    │  │  :8080      │  │    (ACME/Let's Encrypt)       │ │  │
    │  │  └───────┬───────┘  └───────┬───────┘  └──────┬──────┘  └───────────────────────────────┘ │  │
    │  └──────────┼──────────────────┼─────────────────┼───────────────────────────────────────────┘  │
    │             │                  │                 │                                              │
    │  ┌──────────┼──────────────────┼─────────────────┼───────────────────────────────────────────┐  │
    │  │          │    Authentication & Authorization  │                                           │  │
    │  │          │         (JWT, SASL, API Keys)      │                                           │  │
    │  └──────────┼──────────────────┼─────────────────┼───────────────────────────────────────────┘  │
    │             │                  │                 │                                              │
    │  ┌──────────▼──────────────────▼─────────────────▼───────────────────────────────────────────┐  │
    │  │                              Filter Pipeline                                              │  │
    │  │  ┌─────────┐  ┌─────────┐  ┌───────────┐  ┌─────────────────┐  ┌────────────────────────┐ │  │
    │  │  │ Rspamd  │→ │ ClamAV  │→ │ Rate Limit│→ │ LLM Categorizer │→ │    Custom Filters      │ │  │
    │  │  │ (Spam)  │  │ (Virus) │  │           │  │ (OpenAI/Claude) │  │    (Plugin System)     │ │  │
    │  │  └─────────┘  └─────────┘  └───────────┘  └─────────────────┘  └────────────────────────┘ │  │
    │  └──────────────────────────────────────┬────────────────────────────────────────────────────┘  │
    │                                         │                                                       │
    │  ┌──────────────────────────────────────▼────────────────────────────────────────────────────┐  │
    │  │                               Event Bus (Pub/Sub)                                         │  │
    │  │  Events: message.received, message.sent, user.login, filter.matched, certificate.renewed │  │
    │  │  Subscribers: Webhook Dispatcher, Audit Logger, Metrics Collector                        │  │
    │  └──────────────────────────────────────┬────────────────────────────────────────────────────┘  │
    │                                         │                                                       │
    │  ┌──────────────────────────────────────▼────────────────────────────────────────────────────┐  │
    │  │                              Storage Layer                                                │  │
    │  │  ┌─────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────────┐  │  │
    │  │  │      PostgreSQL         │  │       Maildir          │  │      Outbound Queue        │  │  │
    │  │  │  - Users & Domains      │  │  - Message Bodies      │  │  - Delivery Workers        │  │  │
    │  │  │  - Mailbox Metadata     │  │  - Attachments         │  │  - Retry Logic             │  │  │
    │  │  │  - Indexes              │  │  - One file/message    │  │  - Bounce Handling         │  │  │
    │  │  └─────────────────────────┘  └────────────────────────┘  └────────────────────────────┘  │  │
    │  └───────────────────────────────────────────────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Component Overview

### 1. SMTP Server
Handles email sending and receiving via SMTP protocol.

**Ports:**
- `25` - Standard SMTP (with STARTTLS)
- `465` - Implicit TLS (SMTPS)
- `587` - Submission (authenticated sending)

**Features:**
- Multi-domain support
- SPF/DKIM/DMARC verification
- Rate limiting
- Queue management for outbound mail

**Library:** `emersion/go-smtp`

### 2. IMAP Server
Provides mailbox access for email clients.

**Ports:**
- `143` - Standard IMAP (with STARTTLS)
- `993` - Implicit TLS (IMAPS)

**Features:**
- Full IMAP4rev1 support
- IDLE for push notifications
- Search and sort
- Quota management

**Library:** `emersion/go-imap/v2`

### 3. REST API
HTTP API for management and integration.

**Port:** `8080` (configurable)

**Features:**
- JWT authentication
- Domain/user/mailbox management
- Queue monitoring
- Filter configuration
- Webhook management

**Library:** `go-chi/chi`

### 4. Filter Pipeline
Chain of responsibility pattern for message processing.

**Built-in Filters:**
- **Rspamd** - Spam detection and scoring
- **ClamAV** - Virus scanning
- **Rate Limiter** - Per-IP/sender throttling
- **LLM Categorizer** - AI-powered email classification

**Extensibility:**
- Plugin interface for custom filters
- Configuration-driven filter chain
- Per-domain filter settings

### 5. Event Bus
Pub/sub system for decoupled event handling.

**Core Events:**
```go
message.received    // New inbound message
message.sent        // Outbound delivery success
message.bounced     // Delivery failure
message.deleted     // Message removed
user.login          // Authentication event
mailbox.created     // New mailbox
filter.matched      // Filter rule triggered
spam.detected       // Spam threshold exceeded
virus.detected      // Malware found
certificate.renewed // TLS cert updated
```

**Subscribers:**
- Webhook dispatcher
- Audit logger
- Metrics collector
- Custom handlers

### 6. Storage Layer

**PostgreSQL** - Relational data:
- Domain configuration
- User accounts
- Mailbox metadata
- Message indexes
- Filter rules
- Audit logs

**Maildir** - Message storage:
- Industry-standard format
- One file per message
- Easy backup and migration
- Filesystem-based

### 7. Certificate Manager
Automatic TLS certificate management.

**Providers:**
- Let's Encrypt
- ZeroSSL

**Features:**
- Automatic acquisition
- Auto-renewal
- Per-domain certificates
- Certificate caching

## Data Flow

### Inbound Email Flow

```
1. TCP Connection → SMTP Server (port 25/465/587)
2. TLS Handshake ← Certificate Manager
3. EHLO/HELO → Session Created
4. AUTH (if submission) → User Authentication
5. MAIL FROM → SPF Check
6. RCPT TO → Recipient Validation
7. DATA → Message Received
   ├→ DKIM Verification
   ├→ Filter Pipeline
   │   ├→ Rspamd (spam score)
   │   ├→ ClamAV (virus scan)
   │   ├→ Rate Limiter
   │   ├→ LLM Categorizer
   │   └→ Custom Filters
   ├→ Delivery Decision (accept/reject/quarantine)
   └→ Storage (Maildir + PostgreSQL)
8. Event Publication → message.received
9. SMTP Response → Client
```

### Outbound Email Flow

```
1. Message Submission (SMTP or API)
2. Authentication Required
3. Message Validation
4. DKIM Signing
5. Queue Insertion
6. Delivery Worker
   ├→ DNS MX Lookup
   ├→ Remote SMTP Connection
   ├→ TLS Negotiation
   └→ Delivery Attempt
7. Result Handling
   ├→ Success: Remove from queue
   ├→ Temp Failure: Schedule retry
   └→ Perm Failure: Generate bounce
8. Event Publication
```

### IMAP Access Flow

```
1. TCP Connection → IMAP Server (port 143/993)
2. TLS Handshake
3. LOGIN/AUTHENTICATE → User Validation
4. SELECT mailbox → Load from PostgreSQL + Maildir
5. Operations:
   ├→ FETCH → Read from Maildir
   ├→ STORE → Update flags in PostgreSQL
   ├→ COPY/MOVE → Maildir operations
   ├→ SEARCH → Query PostgreSQL indexes
   └→ IDLE → Subscribe to updates
6. Event Publication (as applicable)
```

## Database Schema Overview

```sql
-- Core tables
domains        -- Domain configuration
users          -- User accounts
mailboxes      -- IMAP folders/mailboxes
messages       -- Message metadata and indexes
aliases        -- Email aliases/forwarding

-- Queue
queue          -- Outbound message queue

-- Configuration
filter_rules   -- Per-user filter rules
webhooks       -- Webhook configurations

-- Audit
audit_log      -- System audit trail
```

See `migrations/001_initial_schema.sql` for complete schema.

## Configuration Hierarchy

```yaml
server:
  smtp:           # SMTP server settings
  imap:           # IMAP server settings
  api:            # REST API settings

storage:
  database:       # PostgreSQL connection
  maildir:        # Maildir path configuration

security:
  tls:            # TLS/certificate settings
  auth:           # Authentication settings

filters:
  rspamd:         # Rspamd integration
  clamav:         # ClamAV integration
  llm:            # LLM categorization

events:
  webhooks:       # Webhook configuration
```

See [Configuration Reference](./configuration.md) for all options.

## Key Design Decisions

1. **Maildir over Database BLOBs** - Better performance, easier backup, industry standard
2. **PostgreSQL for Metadata** - Full-text search, JSONB flexibility, proven reliability
3. **emersion/* Libraries** - Most mature Go email libraries, active maintenance
4. **Plugin Architecture** - Extensible without core modifications
5. **Event-Driven** - Loose coupling, easy integration, audit trail
6. **Multi-Provider LLM** - Flexibility in AI service choice
