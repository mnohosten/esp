# Phase 6: REST API

## Overview

**Goal**: Implement a comprehensive REST API for managing domains, users, mailboxes, messages, and system configuration.

**Dependencies**: Phase 1 (Foundation), Phase 3 (Storage)

**Estimated Complexity**: Medium

## Prerequisites

- Phase 1 and Phase 3 completed
- Understanding of REST API design principles
- Understanding of JWT authentication

## Deliverables

1. HTTP server with chi router
2. JWT authentication
3. Domain management API
4. User management API
5. Mailbox and message API
6. Filter and webhook management
7. Queue monitoring
8. OpenAPI documentation

## Core Components

### 1. HTTP Server

**File**: `internal/api/server.go`

```go
// Server is the REST API server
type Server struct {
    router     chi.Router
    config     config.APIConfig
    db         *database.DB
    logger     *slog.Logger
    httpServer *http.Server
}

// New creates a new API server
func New(cfg config.APIConfig, db *database.DB, logger *slog.Logger) *Server

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error
```

### 2. Router Setup

**File**: `internal/api/router.go`

```go
func (s *Server) setupRoutes() {
    r := chi.NewRouter()

    // Global middleware
    r.Use(middleware.RequestID)
    r.Use(middleware.RealIP)
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(middleware.Timeout(60 * time.Second))

    // CORS if enabled
    if s.config.EnableCORS {
        r.Use(cors.Handler(cors.Options{
            AllowedOrigins:   s.config.CORSOrigins,
            AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
            AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
            AllowCredentials: true,
            MaxAge:           300,
        }))
    }

    // Health check (no auth)
    r.Get("/health", s.handleHealth)

    // API routes
    r.Route("/api/v1", func(r chi.Router) {
        // Auth routes (no auth required)
        r.Route("/auth", func(r chi.Router) {
            r.Post("/login", s.handleLogin)
            r.Post("/refresh", s.handleRefresh)
        })

        // Protected routes
        r.Group(func(r chi.Router) {
            r.Use(s.authMiddleware)

            r.Get("/auth/me", s.handleMe)
            r.Post("/auth/logout", s.handleLogout)

            // Domain management (admin only)
            r.Route("/domains", func(r chi.Router) {
                r.Use(s.adminMiddleware)
                r.Get("/", s.handleListDomains)
                r.Post("/", s.handleCreateDomain)
                r.Get("/{domainID}", s.handleGetDomain)
                r.Put("/{domainID}", s.handleUpdateDomain)
                r.Delete("/{domainID}", s.handleDeleteDomain)
                r.Get("/{domainID}/dns", s.handleGetDNSRecords)
                r.Post("/{domainID}/dkim/rotate", s.handleRotateDKIM)
            })

            // User management
            r.Route("/users", func(r chi.Router) {
                r.Get("/", s.handleListUsers)
                r.Post("/", s.handleCreateUser)
                r.Get("/{userID}", s.handleGetUser)
                r.Put("/{userID}", s.handleUpdateUser)
                r.Delete("/{userID}", s.handleDeleteUser)
                r.Put("/{userID}/password", s.handleChangePassword)
                r.Get("/{userID}/quota", s.handleGetQuota)
            })

            // Alias management
            r.Route("/aliases", func(r chi.Router) {
                r.Get("/", s.handleListAliases)
                r.Post("/", s.handleCreateAlias)
                r.Get("/{aliasID}", s.handleGetAlias)
                r.Put("/{aliasID}", s.handleUpdateAlias)
                r.Delete("/{aliasID}", s.handleDeleteAlias)
            })

            // Mailbox management
            r.Route("/mailboxes", func(r chi.Router) {
                r.Get("/", s.handleListMailboxes)
                r.Post("/", s.handleCreateMailbox)
                r.Get("/{mailboxID}", s.handleGetMailbox)
                r.Put("/{mailboxID}", s.handleUpdateMailbox)
                r.Delete("/{mailboxID}", s.handleDeleteMailbox)
                r.Get("/{mailboxID}/messages", s.handleListMessages)
            })

            // Message management
            r.Route("/messages", func(r chi.Router) {
                r.Get("/{messageID}", s.handleGetMessage)
                r.Get("/{messageID}/raw", s.handleGetRawMessage)
                r.Put("/{messageID}/flags", s.handleUpdateFlags)
                r.Post("/{messageID}/move", s.handleMoveMessage)
                r.Delete("/{messageID}", s.handleDeleteMessage)
            })

            // Queue management (admin only)
            r.Route("/queue", func(r chi.Router) {
                r.Use(s.adminMiddleware)
                r.Get("/", s.handleListQueue)
                r.Get("/{queueID}", s.handleGetQueueItem)
                r.Delete("/{queueID}", s.handleCancelQueue)
                r.Post("/{queueID}/retry", s.handleRetryQueue)
            })

            // Filter rules
            r.Route("/filters", func(r chi.Router) {
                r.Get("/", s.handleListFilters)
                r.Post("/", s.handleCreateFilter)
                r.Get("/{filterID}", s.handleGetFilter)
                r.Put("/{filterID}", s.handleUpdateFilter)
                r.Delete("/{filterID}", s.handleDeleteFilter)
                r.Post("/test", s.handleTestFilter)
            })

            // Webhooks
            r.Route("/webhooks", func(r chi.Router) {
                r.Get("/", s.handleListWebhooks)
                r.Post("/", s.handleCreateWebhook)
                r.Get("/{webhookID}", s.handleGetWebhook)
                r.Put("/{webhookID}", s.handleUpdateWebhook)
                r.Delete("/{webhookID}", s.handleDeleteWebhook)
                r.Post("/{webhookID}/test", s.handleTestWebhook)
            })

            // Statistics
            r.Route("/stats", func(r chi.Router) {
                r.Get("/overview", s.handleStatsOverview)
                r.Get("/messages", s.handleStatsMessages)
                r.Get("/queue", s.handleStatsQueue)
                r.Get("/domains/{domainID}", s.handleStatsDomain)
            })
        })

        // Admin routes
        r.Route("/admin", func(r chi.Router) {
            r.Use(s.authMiddleware)
            r.Use(s.adminMiddleware)
            r.Get("/health", s.handleAdminHealth)
            r.Get("/metrics", s.handleMetrics)
            r.Post("/reload", s.handleReload)
            r.Get("/certificates", s.handleCertificates)
        })
    })

    s.router = r
}
```

### 3. Authentication Middleware

**File**: `internal/api/middleware/auth.go`

```go
// JWTAuth handles JWT authentication
type JWTAuth struct {
    secret []byte
    expiry time.Duration
}

// Claims for JWT token
type Claims struct {
    UserID   uuid.UUID `json:"user_id"`
    Email    string    `json:"email"`
    DomainID uuid.UUID `json:"domain_id"`
    IsAdmin  bool      `json:"is_admin"`
    jwt.RegisteredClaims
}

// GenerateToken generates a new JWT token
func (j *JWTAuth) GenerateToken(user *user.User) (string, error)

// ValidateToken validates and parses a JWT token
func (j *JWTAuth) ValidateToken(tokenString string) (*Claims, error)

// Middleware returns authentication middleware
func (j *JWTAuth) Middleware(next http.Handler) http.Handler
```

### 4. Request/Response Types

**File**: `internal/api/types.go`

```go
// API Response wrapper
type Response struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data,omitempty"`
    Error   *ErrorInfo  `json:"error,omitempty"`
    Meta    *Meta       `json:"meta,omitempty"`
}

type ErrorInfo struct {
    Code    string                 `json:"code"`
    Message string                 `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

type Meta struct {
    Page       int `json:"page,omitempty"`
    PerPage    int `json:"per_page,omitempty"`
    Total      int `json:"total,omitempty"`
    TotalPages int `json:"total_pages,omitempty"`
}

// Domain requests/responses
type CreateDomainRequest struct {
    Name           string `json:"name" validate:"required,fqdn"`
    MaxMailboxSize int64  `json:"max_mailbox_size"`
    MaxMessageSize int64  `json:"max_message_size"`
}

type DomainResponse struct {
    ID             uuid.UUID  `json:"id"`
    Name           string     `json:"name"`
    Enabled        bool       `json:"enabled"`
    DKIMSelector   string     `json:"dkim_selector,omitempty"`
    MaxMailboxSize int64      `json:"max_mailbox_size"`
    MaxMessageSize int64      `json:"max_message_size"`
    CreatedAt      time.Time  `json:"created_at"`
    UpdatedAt      time.Time  `json:"updated_at"`
}

// User requests/responses
type CreateUserRequest struct {
    Username    string `json:"username" validate:"required,alphanum"`
    Email       string `json:"email" validate:"required,email"`
    Password    string `json:"password" validate:"required,min=8"`
    DisplayName string `json:"display_name"`
    QuotaBytes  int64  `json:"quota_bytes"`
    IsAdmin     bool   `json:"is_admin"`
}

type UserResponse struct {
    ID          uuid.UUID  `json:"id"`
    Username    string     `json:"username"`
    Email       string     `json:"email"`
    DisplayName string     `json:"display_name"`
    Enabled     bool       `json:"enabled"`
    IsAdmin     bool       `json:"is_admin"`
    QuotaBytes  int64      `json:"quota_bytes"`
    UsedBytes   int64      `json:"used_bytes"`
    CreatedAt   time.Time  `json:"created_at"`
    LastLogin   *time.Time `json:"last_login,omitempty"`
}

// Login request/response
type LoginRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
    Token     string       `json:"token"`
    ExpiresAt time.Time    `json:"expires_at"`
    User      UserResponse `json:"user"`
}

// Message response
type MessageResponse struct {
    ID          uuid.UUID         `json:"id"`
    UID         uint32            `json:"uid"`
    MessageID   string            `json:"message_id"`
    Subject     string            `json:"subject"`
    From        string            `json:"from"`
    To          []string          `json:"to"`
    Cc          []string          `json:"cc,omitempty"`
    Date        time.Time         `json:"date"`
    Size        int64             `json:"size"`
    Flags       []string          `json:"flags"`
    HasAttachments bool           `json:"has_attachments"`
    Preview     string            `json:"preview,omitempty"`
}
```

### 5. Handler Examples

**File**: `internal/api/handlers/domains.go`

```go
func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
    var req CreateDomainRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.respondError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
        return
    }

    if err := s.validator.Struct(req); err != nil {
        s.respondValidationError(w, err)
        return
    }

    domain, err := s.domains.Create(r.Context(), req.Name, req.MaxMailboxSize, req.MaxMessageSize)
    if err != nil {
        if errors.Is(err, domain.ErrDomainExists) {
            s.respondError(w, http.StatusConflict, "DOMAIN_EXISTS", "domain already exists")
            return
        }
        s.respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
        return
    }

    s.respondJSON(w, http.StatusCreated, DomainResponse{
        ID:             domain.ID,
        Name:           domain.Name,
        Enabled:        domain.Enabled,
        MaxMailboxSize: domain.MaxMailboxSize,
        MaxMessageSize: domain.MaxMessageSize,
        CreatedAt:      domain.CreatedAt,
        UpdatedAt:      domain.UpdatedAt,
    })
}
```

## API Endpoints Summary

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/login | Authenticate user |
| POST | /api/v1/auth/refresh | Refresh token |
| POST | /api/v1/auth/logout | Invalidate token |
| GET | /api/v1/auth/me | Get current user |

### Domains (Admin)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/domains | List domains |
| POST | /api/v1/domains | Create domain |
| GET | /api/v1/domains/{id} | Get domain |
| PUT | /api/v1/domains/{id} | Update domain |
| DELETE | /api/v1/domains/{id} | Delete domain |
| GET | /api/v1/domains/{id}/dns | Get DNS records |
| POST | /api/v1/domains/{id}/dkim/rotate | Rotate DKIM key |

### Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/users | List users |
| POST | /api/v1/users | Create user |
| GET | /api/v1/users/{id} | Get user |
| PUT | /api/v1/users/{id} | Update user |
| DELETE | /api/v1/users/{id} | Delete user |
| PUT | /api/v1/users/{id}/password | Change password |
| GET | /api/v1/users/{id}/quota | Get quota usage |

### Mailboxes & Messages
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/mailboxes | List mailboxes |
| POST | /api/v1/mailboxes | Create mailbox |
| GET | /api/v1/mailboxes/{id}/messages | List messages |
| GET | /api/v1/messages/{id} | Get message |
| GET | /api/v1/messages/{id}/raw | Get raw message |
| PUT | /api/v1/messages/{id}/flags | Update flags |
| POST | /api/v1/messages/{id}/move | Move message |
| DELETE | /api/v1/messages/{id} | Delete message |

## Task Breakdown

### Server Setup
- [ ] Set up chi router
- [ ] Configure middleware stack
- [ ] Implement graceful shutdown
- [ ] Add request logging

### Authentication
- [ ] Implement JWT generation
- [ ] Implement JWT validation
- [ ] Create auth middleware
- [ ] Handle token refresh
- [ ] Add admin role checking

### Domain API
- [ ] List domains
- [ ] Create domain
- [ ] Get domain details
- [ ] Update domain
- [ ] Delete domain
- [ ] Generate DNS records
- [ ] DKIM key rotation

### User API
- [ ] List users (with filtering)
- [ ] Create user
- [ ] Get user details
- [ ] Update user
- [ ] Delete user
- [ ] Change password
- [ ] Quota reporting

### Mailbox & Message API
- [ ] List mailboxes
- [ ] Create/delete mailboxes
- [ ] List messages (paginated)
- [ ] Get message details
- [ ] Get raw message
- [ ] Update message flags
- [ ] Move/delete messages

### Additional APIs
- [ ] Alias management
- [ ] Filter rules management
- [ ] Webhook management
- [ ] Queue monitoring
- [ ] Statistics endpoints

### Documentation
- [ ] Generate OpenAPI spec
- [ ] Add API documentation

## Configuration

```yaml
server:
  api:
    enabled: true
    listen_addr: ":8080"
    jwt_secret: "your-secret-key-change-in-production"
    jwt_expiry: 24h
    rate_limit: 100
    enable_cors: true
    cors_origins:
      - "http://localhost:3000"
      - "https://admin.example.com"
```

## Testing

### Unit Tests
- JWT generation/validation
- Request validation
- Handler logic

### Integration Tests
- Full API workflows
- Authentication flows
- CRUD operations

### Test with curl
```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin"}' | jq -r '.data.token')

# List domains
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/domains

# Create user
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","email":"newuser@example.com","password":"password123"}'
```

## Completion Criteria

- [ ] All CRUD endpoints implemented
- [ ] JWT authentication works
- [ ] Admin authorization works
- [ ] Pagination works
- [ ] Validation works
- [ ] Error handling consistent
- [ ] OpenAPI documentation generated
- [ ] All tests pass

## Next Phase

Once Phase 6 is complete, proceed to [Phase 7: Event System](./phase-07-events.md).
