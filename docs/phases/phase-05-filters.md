# Phase 5: Filter Pipeline

## Overview

**Goal**: Implement an extensible message filtering system with built-in spam and virus scanning integration.

**Dependencies**: Phase 1 (Foundation), Phase 2 (SMTP)

**Estimated Complexity**: Medium

## Prerequisites

- Phase 1 and Phase 2 completed
- Rspamd server available (optional)
- ClamAV server available (optional)

## Deliverables

1. Filter chain architecture
2. Rspamd integration
3. ClamAV integration
4. Rate limiting filter
5. Custom filter framework
6. Plugin loading system
7. Per-domain filter configuration

## Core Components

### 1. Filter Interface

**File**: `internal/filter/filter.go`

```go
// Filter processes messages and returns a result
type Filter interface {
    // Name returns the filter name
    Name() string

    // Priority returns execution order (lower = earlier)
    Priority() int

    // Process processes a message
    Process(ctx context.Context, msg *Message) (*Result, error)
}

// Message represents a message being filtered
type Message struct {
    ID          string
    From        string
    To          []string
    Subject     string
    Headers     map[string][]string
    Body        []byte
    Size        int64
    ClientIP    net.IP
    ClientHost  string
    HELO        string
    AuthUser    string
    Domain      string
}

// Result represents filter processing result
type Result struct {
    Action      Action
    Score       float64
    Reason      string
    Headers     map[string]string   // Headers to add
    Tags        []string            // Tags for categorization
    Metadata    map[string]any      // Additional metadata
    TargetFolder string             // Override delivery folder
}

// Action defines what to do with the message
type Action int

const (
    ActionAccept Action = iota
    ActionReject
    ActionQuarantine
    ActionDefer
    ActionDiscard
)
```

### 2. Filter Chain

**File**: `internal/filter/chain.go`

```go
// Chain orchestrates filter execution
type Chain struct {
    filters   []Filter
    eventBus  *event.Bus
    logger    *slog.Logger
    mu        sync.RWMutex
}

// New creates a new filter chain
func NewChain(eventBus *event.Bus, logger *slog.Logger) *Chain

// Register adds a filter to the chain
func (c *Chain) Register(filter Filter)

// Unregister removes a filter
func (c *Chain) Unregister(name string)

// Process runs all filters on a message
func (c *Chain) Process(ctx context.Context, msg *Message) (*Result, error) {
    finalResult := &Result{Action: ActionAccept}

    // Sort filters by priority
    filters := c.sortedFilters()

    for _, filter := range filters {
        result, err := filter.Process(ctx, msg)
        if err != nil {
            c.logger.Error("filter error",
                "filter", filter.Name(),
                "error", err,
            )
            // Emit error event but continue
            c.eventBus.Publish("filter.error", FilterErrorEvent{
                Filter:    filter.Name(),
                MessageID: msg.ID,
                Error:     err.Error(),
            })
            continue
        }

        // Merge results
        finalResult = c.mergeResults(finalResult, result)

        // Emit filter match event
        if result.Action != ActionAccept || len(result.Tags) > 0 {
            c.eventBus.Publish("filter.matched", FilterMatchEvent{
                Filter:    filter.Name(),
                MessageID: msg.ID,
                Action:    result.Action,
                Score:     result.Score,
                Tags:      result.Tags,
            })
        }

        // Stop on reject/discard
        if result.Action == ActionReject || result.Action == ActionDiscard {
            break
        }
    }

    return finalResult, nil
}

// mergeResults combines filter results
func (c *Chain) mergeResults(existing, new *Result) *Result
```

### 3. Rspamd Filter

**File**: `internal/filter/rspamd/rspamd.go`

```go
// Filter implements rspamd spam checking
type Filter struct {
    client *Client
    config Config
    logger *slog.Logger
}

// Config for rspamd integration
type Config struct {
    URL             string        `mapstructure:"url"`
    Password        string        `mapstructure:"password"`
    Timeout         time.Duration `mapstructure:"timeout"`
    RejectScore     float64       `mapstructure:"reject_score"`
    QuarantineScore float64       `mapstructure:"quarantine_score"`
    AddHeaders      bool          `mapstructure:"add_headers"`
}

// Client wraps rspamd HTTP API
type Client struct {
    httpClient *http.Client
    baseURL    string
    password   string
}

func (f *Filter) Name() string { return "rspamd" }
func (f *Filter) Priority() int { return 100 }

func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
    // Build rspamd request
    req := &CheckRequest{
        IP:       msg.ClientIP.String(),
        Hostname: msg.ClientHost,
        HELO:     msg.HELO,
        From:     msg.From,
        Rcpt:     msg.To,
        User:     msg.AuthUser,
    }

    // Send to rspamd
    resp, err := f.client.Check(ctx, msg.Body, req)
    if err != nil {
        return nil, fmt.Errorf("rspamd check failed: %w", err)
    }

    result := &filter.Result{
        Score: resp.Score,
        Tags:  resp.Symbols,
        Metadata: map[string]any{
            "rspamd_action":  resp.Action,
            "rspamd_score":   resp.Score,
            "rspamd_symbols": resp.Symbols,
        },
    }

    // Add spam headers if configured
    if f.config.AddHeaders {
        result.Headers = map[string]string{
            "X-Spam-Score":  fmt.Sprintf("%.2f", resp.Score),
            "X-Spam-Status": resp.Action,
        }
        if len(resp.Symbols) > 0 {
            result.Headers["X-Spam-Symbols"] = strings.Join(resp.Symbols, ", ")
        }
    }

    // Determine action
    switch {
    case resp.Score >= f.config.RejectScore:
        result.Action = filter.ActionReject
        result.Reason = fmt.Sprintf("spam score %.2f exceeds threshold", resp.Score)
    case resp.Score >= f.config.QuarantineScore:
        result.Action = filter.ActionQuarantine
        result.TargetFolder = "Junk"
    default:
        result.Action = filter.ActionAccept
    }

    return result, nil
}
```

### 4. ClamAV Filter

**File**: `internal/filter/clamav/clamav.go`

```go
// Filter implements ClamAV virus scanning
type Filter struct {
    client *Client
    config Config
    logger *slog.Logger
}

// Config for ClamAV integration
type Config struct {
    Address string        `mapstructure:"address"` // tcp:// or unix://
    Timeout time.Duration `mapstructure:"timeout"`
}

// Client wraps clamd protocol
type Client struct {
    network string
    address string
    timeout time.Duration
}

func (f *Filter) Name() string { return "clamav" }
func (f *Filter) Priority() int { return 50 } // Run before spam

func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
    result, err := f.client.ScanStream(ctx, bytes.NewReader(msg.Body))
    if err != nil {
        return nil, fmt.Errorf("clamav scan failed: %w", err)
    }

    filterResult := &filter.Result{
        Action: filter.ActionAccept,
        Metadata: map[string]any{
            "clamav_scanned": true,
        },
    }

    if result.Infected {
        filterResult.Action = filter.ActionReject
        filterResult.Reason = fmt.Sprintf("virus detected: %s", result.Virus)
        filterResult.Tags = []string{"virus", result.Virus}
        filterResult.Metadata["clamav_virus"] = result.Virus

        // Emit virus detected event
        return filterResult, nil
    }

    return filterResult, nil
}

// ScanResult from ClamAV
type ScanResult struct {
    Infected bool
    Virus    string
    Error    string
}
```

### 5. Rate Limiter Filter

**File**: `internal/filter/ratelimit/ratelimit.go`

```go
// Filter implements rate limiting
type Filter struct {
    store  RateLimitStore
    config Config
    logger *slog.Logger
}

// Config for rate limiting
type Config struct {
    // Per-IP limits
    IPMessagesPerMinute  int `mapstructure:"ip_messages_per_minute"`
    IPMessagesPerHour    int `mapstructure:"ip_messages_per_hour"`

    // Per-sender limits
    SenderMessagesPerMinute int `mapstructure:"sender_messages_per_minute"`
    SenderMessagesPerHour   int `mapstructure:"sender_messages_per_hour"`

    // Per-recipient limits
    RecipientMessagesPerMinute int `mapstructure:"recipient_messages_per_minute"`
}

// RateLimitStore tracks rate limits
type RateLimitStore interface {
    Increment(ctx context.Context, key string, window time.Duration) (int64, error)
    Get(ctx context.Context, key string) (int64, error)
}

func (f *Filter) Name() string { return "ratelimit" }
func (f *Filter) Priority() int { return 10 } // Run very early

func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
    // Check IP rate
    ipKey := fmt.Sprintf("ip:%s:minute", msg.ClientIP.String())
    count, err := f.store.Increment(ctx, ipKey, time.Minute)
    if err != nil {
        return nil, err
    }
    if int(count) > f.config.IPMessagesPerMinute {
        return &filter.Result{
            Action: filter.ActionDefer,
            Reason: "rate limit exceeded for IP",
        }, nil
    }

    // Check sender rate
    senderKey := fmt.Sprintf("sender:%s:minute", msg.From)
    count, err = f.store.Increment(ctx, senderKey, time.Minute)
    if err != nil {
        return nil, err
    }
    if int(count) > f.config.SenderMessagesPerMinute {
        return &filter.Result{
            Action: filter.ActionDefer,
            Reason: "rate limit exceeded for sender",
        }, nil
    }

    return &filter.Result{Action: filter.ActionAccept}, nil
}
```

### 6. Plugin System

**File**: `internal/plugin/manager.go`

```go
// Manager handles plugin lifecycle
type Manager struct {
    plugins map[string]Plugin
    config  map[string]map[string]any
    logger  *slog.Logger
    mu      sync.RWMutex
}

// Plugin interface for external plugins
type Plugin interface {
    Name() string
    Version() string
    Init(ctx context.Context, config map[string]any) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
}

// FilterPlugin provides a filter
type FilterPlugin interface {
    Plugin
    Filter() filter.Filter
}

// New creates a plugin manager
func NewManager(logger *slog.Logger) *Manager

// Load loads a plugin
func (m *Manager) Load(ctx context.Context, name string, config map[string]any) error

// GetFilter returns filter from a plugin
func (m *Manager) GetFilter(name string) (filter.Filter, error)

// GetAllFilters returns all filter plugins
func (m *Manager) GetAllFilters() []filter.Filter
```

## Task Breakdown

### Filter Chain
- [ ] Design filter interface
- [ ] Implement filter chain orchestration
- [ ] Add filter registration/unregistration
- [ ] Implement result merging
- [ ] Add filter error handling
- [ ] Emit filter events

### Rspamd Integration
- [ ] Implement rspamd HTTP client
- [ ] Create rspamd filter
- [ ] Parse rspamd responses
- [ ] Map scores to actions
- [ ] Add spam headers
- [ ] Handle rspamd unavailability

### ClamAV Integration
- [ ] Implement clamd protocol client
- [ ] Support TCP and Unix socket
- [ ] Create ClamAV filter
- [ ] Handle scan results
- [ ] Handle ClamAV unavailability

### Rate Limiting
- [ ] Design rate limit storage (Redis/memory)
- [ ] Implement per-IP limiting
- [ ] Implement per-sender limiting
- [ ] Implement per-recipient limiting
- [ ] Add sliding window support

### Custom Filters
- [ ] Define plugin interface
- [ ] Implement plugin loader
- [ ] Support configuration per plugin
- [ ] Add filter factory

### Per-Domain Configuration
- [ ] Allow filter config per domain
- [ ] Support filter enable/disable per domain
- [ ] Custom thresholds per domain

## Configuration

```yaml
filters:
  # Global enable/disable
  enabled: true

  # Filter chain settings
  chain:
    fail_open: true  # Continue on filter error

  rspamd:
    enabled: true
    url: "http://localhost:11333"
    password: ""
    timeout: 30s
    reject_score: 15.0
    quarantine_score: 6.0
    add_headers: true

  clamav:
    enabled: true
    address: "tcp://localhost:3310"
    timeout: 60s

  ratelimit:
    enabled: true
    ip_messages_per_minute: 30
    ip_messages_per_hour: 300
    sender_messages_per_minute: 10
    sender_messages_per_hour: 100
    recipient_messages_per_minute: 100

  # Custom plugins
  plugins:
    - name: custom-filter
      path: /etc/esp/plugins/custom.so
      config:
        key: value
```

## Testing

### Unit Tests
- Filter chain execution order
- Result merging logic
- Rate limit calculations
- Mock rspamd/clamav responses

### Integration Tests
- Full filter pipeline
- Rspamd integration (requires rspamd)
- ClamAV integration (requires clamd)
- Rate limiting behavior

### Test Setup
```bash
# Run rspamd for testing
docker run -d --name rspamd -p 11333:11333 rspamd/rspamd

# Run ClamAV for testing
docker run -d --name clamav -p 3310:3310 clamav/clamav
```

## Completion Criteria

- [ ] Filter chain processes messages
- [ ] Rspamd integration works
- [ ] ClamAV integration works
- [ ] Rate limiting prevents abuse
- [ ] Custom filters can be added
- [ ] Per-domain config works
- [ ] Filter events are emitted
- [ ] All tests pass

## Next Phase

Once Phase 5 is complete, proceed to [Phase 6: REST API](./phase-06-api.md).
