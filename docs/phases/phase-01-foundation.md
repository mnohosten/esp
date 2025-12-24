# Phase 1: Foundation & Core Infrastructure

## Overview

**Goal**: Establish project structure, configuration system, database layer, and core utilities that all subsequent phases will build upon.

**Estimated Complexity**: Medium

## Prerequisites

- Go 1.21+
- PostgreSQL 14+
- Make

## Deliverables

1. Complete project directory structure
2. Working configuration system with YAML + env override
3. PostgreSQL connection with migration support
4. Structured logging implementation
5. CLI framework with basic commands
6. Makefile for build automation

## Directory Structure

```
esp-solution/
├── cmd/
│   ├── esp-server/
│   │   └── main.go              # Main server entry point
│   └── esp-cli/
│       └── main.go              # CLI management tool
├── internal/
│   ├── config/
│   │   ├── config.go            # Configuration structures
│   │   ├── loader.go            # Config file loading
│   │   └── validate.go          # Configuration validation
│   ├── database/
│   │   ├── postgres.go          # PostgreSQL connection
│   │   ├── migrate.go           # Migration runner
│   │   └── health.go            # Connection health checks
│   ├── logging/
│   │   ├── logger.go            # Slog-based logging
│   │   └── context.go           # Contextual logging helpers
│   └── version/
│       └── version.go           # Build version info
├── pkg/                         # Public packages (future use)
├── migrations/
│   └── 001_initial_schema.sql   # Initial database schema
├── configs/
│   └── server.yaml.example      # Example configuration
├── docs/                        # Documentation
├── go.mod
├── go.sum
├── Makefile
├── TODO.md
├── CHANGELOG.md
└── README.md
```

## Task Breakdown

### 1. Project Setup

#### 1.1 Initialize Go Module
```bash
go mod init github.com/mnohosten/esp
```

#### 1.2 Create Directory Structure
```bash
mkdir -p cmd/esp-server cmd/esp-cli
mkdir -p internal/config internal/database internal/logging internal/version
mkdir -p pkg migrations configs docs/phases docs/api docs/deployment docs/development
```

#### 1.3 Install Core Dependencies
```bash
go get github.com/spf13/viper
go get github.com/spf13/cobra
go get github.com/jackc/pgx/v5
```

### 2. Configuration System

#### 2.1 Configuration Structures

**File**: `internal/config/config.go`

```go
package config

import "time"

// Config is the root configuration structure
type Config struct {
    Server   ServerConfig   `mapstructure:"server"`
    Storage  StorageConfig  `mapstructure:"storage"`
    Security SecurityConfig `mapstructure:"security"`
    Logging  LoggingConfig  `mapstructure:"logging"`
}

// ServerConfig contains all server-related settings
type ServerConfig struct {
    SMTP SMTPConfig `mapstructure:"smtp"`
    IMAP IMAPConfig `mapstructure:"imap"`
    API  APIConfig  `mapstructure:"api"`
}

// SMTPConfig defines SMTP server settings
type SMTPConfig struct {
    Enabled         bool          `mapstructure:"enabled"`
    ListenAddr      string        `mapstructure:"listen_addr"`       // :25
    SubmissionAddr  string        `mapstructure:"submission_addr"`   // :587
    ImplicitTLSAddr string        `mapstructure:"implicit_tls_addr"` // :465
    Hostname        string        `mapstructure:"hostname"`
    MaxMessageSize  int64         `mapstructure:"max_message_size"`
    MaxRecipients   int           `mapstructure:"max_recipients"`
    ReadTimeout     time.Duration `mapstructure:"read_timeout"`
    WriteTimeout    time.Duration `mapstructure:"write_timeout"`
    RequireTLS      bool          `mapstructure:"require_tls"`
}

// IMAPConfig defines IMAP server settings
type IMAPConfig struct {
    Enabled         bool          `mapstructure:"enabled"`
    ListenAddr      string        `mapstructure:"listen_addr"`       // :143
    ImplicitTLSAddr string        `mapstructure:"implicit_tls_addr"` // :993
    ReadTimeout     time.Duration `mapstructure:"read_timeout"`
    WriteTimeout    time.Duration `mapstructure:"write_timeout"`
}

// APIConfig defines REST API settings
type APIConfig struct {
    Enabled     bool          `mapstructure:"enabled"`
    ListenAddr  string        `mapstructure:"listen_addr"` // :8080
    JWTSecret   string        `mapstructure:"jwt_secret"`
    JWTExpiry   time.Duration `mapstructure:"jwt_expiry"`
    RateLimit   int           `mapstructure:"rate_limit"`
    EnableCORS  bool          `mapstructure:"enable_cors"`
    CORSOrigins []string      `mapstructure:"cors_origins"`
}

// StorageConfig defines storage settings
type StorageConfig struct {
    Database DatabaseConfig `mapstructure:"database"`
    Maildir  MaildirConfig  `mapstructure:"maildir"`
}

// DatabaseConfig defines PostgreSQL settings
type DatabaseConfig struct {
    Host            string        `mapstructure:"host"`
    Port            int           `mapstructure:"port"`
    User            string        `mapstructure:"user"`
    Password        string        `mapstructure:"password"`
    Database        string        `mapstructure:"database"`
    SSLMode         string        `mapstructure:"ssl_mode"`
    MaxConnections  int           `mapstructure:"max_connections"`
    MaxIdleConns    int           `mapstructure:"max_idle_conns"`
    ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// MaildirConfig defines maildir storage settings
type MaildirConfig struct {
    BasePath string `mapstructure:"base_path"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
    TLS TLSConfig `mapstructure:"tls"`
}

// TLSConfig defines TLS/certificate settings
type TLSConfig struct {
    CertFile    string `mapstructure:"cert_file"`
    KeyFile     string `mapstructure:"key_file"`
    AutoTLS     bool   `mapstructure:"auto_tls"`
    ACMEEmail   string `mapstructure:"acme_email"`
    ACMEDir     string `mapstructure:"acme_dir"`
    ACMEStaging bool   `mapstructure:"acme_staging"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
    Level      string `mapstructure:"level"`  // debug, info, warn, error
    Format     string `mapstructure:"format"` // json, text
    Output     string `mapstructure:"output"` // stdout, file path
    AddSource  bool   `mapstructure:"add_source"`
}
```

#### 2.2 Configuration Loader

**File**: `internal/config/loader.go`

```go
package config

import (
    "fmt"
    "strings"

    "github.com/spf13/viper"
)

// Load reads configuration from file and environment
func Load(configPath string) (*Config, error) {
    v := viper.New()

    // Set defaults
    setDefaults(v)

    // Read config file if provided
    if configPath != "" {
        v.SetConfigFile(configPath)
        if err := v.ReadInConfig(); err != nil {
            return nil, fmt.Errorf("failed to read config: %w", err)
        }
    }

    // Environment variables override
    v.SetEnvPrefix("ESP")
    v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    v.AutomaticEnv()

    var cfg Config
    if err := v.Unmarshal(&cfg); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }

    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("invalid config: %w", err)
    }

    return &cfg, nil
}

func setDefaults(v *viper.Viper) {
    // SMTP defaults
    v.SetDefault("server.smtp.enabled", true)
    v.SetDefault("server.smtp.listen_addr", ":25")
    v.SetDefault("server.smtp.submission_addr", ":587")
    v.SetDefault("server.smtp.implicit_tls_addr", ":465")
    v.SetDefault("server.smtp.max_message_size", 25*1024*1024) // 25MB
    v.SetDefault("server.smtp.max_recipients", 100)
    v.SetDefault("server.smtp.read_timeout", "60s")
    v.SetDefault("server.smtp.write_timeout", "60s")

    // IMAP defaults
    v.SetDefault("server.imap.enabled", true)
    v.SetDefault("server.imap.listen_addr", ":143")
    v.SetDefault("server.imap.implicit_tls_addr", ":993")
    v.SetDefault("server.imap.read_timeout", "30m")
    v.SetDefault("server.imap.write_timeout", "60s")

    // API defaults
    v.SetDefault("server.api.enabled", true)
    v.SetDefault("server.api.listen_addr", ":8080")
    v.SetDefault("server.api.jwt_expiry", "24h")
    v.SetDefault("server.api.rate_limit", 100)

    // Database defaults
    v.SetDefault("storage.database.host", "localhost")
    v.SetDefault("storage.database.port", 5432)
    v.SetDefault("storage.database.database", "esp")
    v.SetDefault("storage.database.ssl_mode", "prefer")
    v.SetDefault("storage.database.max_connections", 25)
    v.SetDefault("storage.database.max_idle_conns", 5)
    v.SetDefault("storage.database.conn_max_lifetime", "1h")

    // Maildir defaults
    v.SetDefault("storage.maildir.base_path", "/var/mail/esp")

    // Logging defaults
    v.SetDefault("logging.level", "info")
    v.SetDefault("logging.format", "json")
    v.SetDefault("logging.output", "stdout")
}
```

#### 2.3 Configuration Validation

**File**: `internal/config/validate.go`

```go
package config

import (
    "errors"
    "fmt"
    "net"
)

// Validate checks the configuration for errors
func (c *Config) Validate() error {
    var errs []error

    // Validate SMTP config
    if c.Server.SMTP.Enabled {
        if err := validateAddr(c.Server.SMTP.ListenAddr, "smtp.listen_addr"); err != nil {
            errs = append(errs, err)
        }
        if c.Server.SMTP.Hostname == "" {
            errs = append(errs, errors.New("smtp.hostname is required"))
        }
    }

    // Validate IMAP config
    if c.Server.IMAP.Enabled {
        if err := validateAddr(c.Server.IMAP.ListenAddr, "imap.listen_addr"); err != nil {
            errs = append(errs, err)
        }
    }

    // Validate API config
    if c.Server.API.Enabled {
        if err := validateAddr(c.Server.API.ListenAddr, "api.listen_addr"); err != nil {
            errs = append(errs, err)
        }
        if c.Server.API.JWTSecret == "" {
            errs = append(errs, errors.New("api.jwt_secret is required"))
        }
    }

    // Validate database config
    if c.Storage.Database.Host == "" {
        errs = append(errs, errors.New("database.host is required"))
    }
    if c.Storage.Database.User == "" {
        errs = append(errs, errors.New("database.user is required"))
    }

    // Validate maildir config
    if c.Storage.Maildir.BasePath == "" {
        errs = append(errs, errors.New("maildir.base_path is required"))
    }

    if len(errs) > 0 {
        return errors.Join(errs...)
    }

    return nil
}

func validateAddr(addr, name string) error {
    if addr == "" {
        return fmt.Errorf("%s is required", name)
    }
    _, _, err := net.SplitHostPort(addr)
    if err != nil {
        return fmt.Errorf("%s is invalid: %w", name, err)
    }
    return nil
}
```

### 3. Database Layer

#### 3.1 PostgreSQL Connection

**File**: `internal/database/postgres.go`

```go
package database

import (
    "context"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/mnohosten/esp/internal/config"
)

// DB wraps the PostgreSQL connection pool
type DB struct {
    Pool *pgxpool.Pool
}

// New creates a new database connection
func New(ctx context.Context, cfg config.DatabaseConfig) (*DB, error) {
    connStr := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
    )

    poolCfg, err := pgxpool.ParseConfig(connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to parse connection string: %w", err)
    }

    poolCfg.MaxConns = int32(cfg.MaxConnections)
    poolCfg.MinConns = int32(cfg.MaxIdleConns)
    poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime

    pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
    if err != nil {
        return nil, fmt.Errorf("failed to create pool: %w", err)
    }

    // Test connection
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    if err := pool.Ping(ctx); err != nil {
        pool.Close()
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    return &DB{Pool: pool}, nil
}

// Close closes the database connection pool
func (db *DB) Close() {
    if db.Pool != nil {
        db.Pool.Close()
    }
}

// Health checks if the database is healthy
func (db *DB) Health(ctx context.Context) error {
    return db.Pool.Ping(ctx)
}
```

#### 3.2 Migration Runner

**File**: `internal/database/migrate.go`

```go
package database

import (
    "context"
    "embed"
    "fmt"
    "io/fs"
    "path/filepath"
    "sort"
    "strings"
)

//go:embed ../../../migrations/*.sql
var migrationsFS embed.FS

// Migrate runs all pending migrations
func (db *DB) Migrate(ctx context.Context) error {
    // Create migrations table if not exists
    _, err := db.Pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT NOW()
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to create migrations table: %w", err)
    }

    // Get applied migrations
    applied := make(map[string]bool)
    rows, err := db.Pool.Query(ctx, "SELECT version FROM schema_migrations")
    if err != nil {
        return fmt.Errorf("failed to query migrations: %w", err)
    }
    defer rows.Close()

    for rows.Next() {
        var version string
        if err := rows.Scan(&version); err != nil {
            return fmt.Errorf("failed to scan migration: %w", err)
        }
        applied[version] = true
    }

    // Get migration files
    files, err := fs.ReadDir(migrationsFS, "migrations")
    if err != nil {
        return fmt.Errorf("failed to read migrations: %w", err)
    }

    var migrations []string
    for _, f := range files {
        if strings.HasSuffix(f.Name(), ".sql") {
            migrations = append(migrations, f.Name())
        }
    }
    sort.Strings(migrations)

    // Apply pending migrations
    for _, migration := range migrations {
        version := strings.TrimSuffix(migration, filepath.Ext(migration))
        if applied[version] {
            continue
        }

        content, err := fs.ReadFile(migrationsFS, filepath.Join("migrations", migration))
        if err != nil {
            return fmt.Errorf("failed to read migration %s: %w", migration, err)
        }

        tx, err := db.Pool.Begin(ctx)
        if err != nil {
            return fmt.Errorf("failed to begin transaction: %w", err)
        }

        if _, err := tx.Exec(ctx, string(content)); err != nil {
            tx.Rollback(ctx)
            return fmt.Errorf("failed to apply migration %s: %w", migration, err)
        }

        if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
            tx.Rollback(ctx)
            return fmt.Errorf("failed to record migration %s: %w", migration, err)
        }

        if err := tx.Commit(ctx); err != nil {
            return fmt.Errorf("failed to commit migration %s: %w", migration, err)
        }
    }

    return nil
}
```

### 4. Initial Database Schema

**File**: `migrations/001_initial_schema.sql`

```sql
-- ESP Initial Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Domains table
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- DKIM configuration
    dkim_selector VARCHAR(255),
    dkim_private_key TEXT,

    -- Limits
    max_mailbox_size BIGINT DEFAULT 1073741824, -- 1GB
    max_message_size BIGINT DEFAULT 26214400,   -- 25MB

    -- Settings (JSONB for flexibility)
    settings JSONB DEFAULT '{}'
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,

    -- Quota
    quota_bytes BIGINT DEFAULT 1073741824, -- 1GB
    used_bytes BIGINT DEFAULT 0,

    -- Settings
    settings JSONB DEFAULT '{}',

    UNIQUE(domain_id, username)
);

-- Mailboxes (IMAP folders)
CREATE TABLE mailboxes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uidnext INTEGER DEFAULT 1,
    subscribed BOOLEAN DEFAULT true,
    special_use VARCHAR(50), -- \Inbox, \Sent, \Drafts, \Trash, \Junk, \Archive
    message_count INTEGER DEFAULT 0,
    unread_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(user_id, name)
);

-- Messages metadata
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mailbox_id UUID NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,

    -- Envelope data
    message_id VARCHAR(255),
    in_reply_to VARCHAR(255),
    subject TEXT,
    from_address VARCHAR(255),
    to_addresses TEXT[],
    cc_addresses TEXT[],
    date TIMESTAMP,

    -- Storage
    size INTEGER NOT NULL,
    storage_path VARCHAR(500) NOT NULL,

    -- IMAP flags
    flags TEXT[] DEFAULT '{}',
    internal_date TIMESTAMP DEFAULT NOW(),

    -- Metadata
    headers_json JSONB,

    -- Search support
    body_text TEXT,

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(mailbox_id, uid)
);

-- Full-text search index
CREATE INDEX messages_fts_idx ON messages
    USING GIN (to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(body_text, '')));

CREATE INDEX messages_mailbox_idx ON messages(mailbox_id);
CREATE INDEX messages_date_idx ON messages(date);
CREATE INDEX messages_from_idx ON messages(from_address);

-- Aliases
CREATE TABLE aliases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(domain_id, source)
);

-- Outbound Queue
CREATE TABLE queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255),
    sender VARCHAR(255) NOT NULL,
    recipient VARCHAR(255) NOT NULL,

    -- Message storage
    message_path VARCHAR(500),
    size INTEGER,

    -- State
    status VARCHAR(20) DEFAULT 'pending',
    priority INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    last_attempt TIMESTAMP,
    next_attempt TIMESTAMP DEFAULT NOW(),
    last_error TEXT,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE INDEX queue_next_attempt_idx ON queue(status, next_attempt);
CREATE INDEX queue_sender_idx ON queue(sender);

-- Webhooks
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID REFERENCES domains(id) ON DELETE CASCADE,
    name VARCHAR(255),
    url VARCHAR(500) NOT NULL,
    events TEXT[] NOT NULL,
    secret VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_triggered TIMESTAMP,
    failure_count INTEGER DEFAULT 0
);

-- Filter Rules
CREATE TABLE filter_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255),
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,

    -- Conditions (JSONB for flexibility)
    conditions JSONB NOT NULL,

    -- Actions
    actions JSONB NOT NULL,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Audit Log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    actor_id UUID,
    actor_ip INET,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB
);

CREATE INDEX audit_log_timestamp_idx ON audit_log(timestamp);
CREATE INDEX audit_log_event_type_idx ON audit_log(event_type);
CREATE INDEX audit_log_actor_idx ON audit_log(actor_id);

-- Update triggers
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domains_updated_at
    BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER mailboxes_updated_at
    BEFORE UPDATE ON mailboxes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER webhooks_updated_at
    BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER filter_rules_updated_at
    BEFORE UPDATE ON filter_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
```

### 5. Logging System

**File**: `internal/logging/logger.go`

```go
package logging

import (
    "context"
    "io"
    "log/slog"
    "os"

    "github.com/mnohosten/esp/internal/config"
)

type contextKey string

const loggerKey contextKey = "logger"

// New creates a new logger based on configuration
func New(cfg config.LoggingConfig) *slog.Logger {
    var level slog.Level
    switch cfg.Level {
    case "debug":
        level = slog.LevelDebug
    case "warn":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    default:
        level = slog.LevelInfo
    }

    var output io.Writer
    if cfg.Output == "stdout" || cfg.Output == "" {
        output = os.Stdout
    } else {
        f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
            output = os.Stdout
        } else {
            output = f
        }
    }

    opts := &slog.HandlerOptions{
        Level:     level,
        AddSource: cfg.AddSource,
    }

    var handler slog.Handler
    if cfg.Format == "json" {
        handler = slog.NewJSONHandler(output, opts)
    } else {
        handler = slog.NewTextHandler(output, opts)
    }

    return slog.New(handler)
}

// WithContext returns a new context with the logger
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
    return context.WithValue(ctx, loggerKey, logger)
}

// FromContext returns the logger from context, or a default logger
func FromContext(ctx context.Context) *slog.Logger {
    if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
        return logger
    }
    return slog.Default()
}

// With returns a logger with additional attributes
func With(logger *slog.Logger, args ...any) *slog.Logger {
    return logger.With(args...)
}
```

### 6. CLI Framework

**File**: `cmd/esp-server/main.go`

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/spf13/cobra"
    "github.com/mnohosten/esp/internal/config"
    "github.com/mnohosten/esp/internal/database"
    "github.com/mnohosten/esp/internal/logging"
    "github.com/mnohosten/esp/internal/version"
)

var cfgFile string

func main() {
    rootCmd := &cobra.Command{
        Use:   "esp-server",
        Short: "ESP - Email Service Platform",
        Long:  "A comprehensive email server solution with SMTP, IMAP, and REST API",
    }

    rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")

    rootCmd.AddCommand(serveCmd())
    rootCmd.AddCommand(migrateCmd())
    rootCmd.AddCommand(versionCmd())

    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func serveCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "serve",
        Short: "Start the ESP server",
        RunE: func(cmd *cobra.Command, args []string) error {
            cfg, err := config.Load(cfgFile)
            if err != nil {
                return fmt.Errorf("failed to load config: %w", err)
            }

            logger := logging.New(cfg.Logging)
            logger.Info("starting ESP server", "version", version.Version)

            ctx, cancel := context.WithCancel(context.Background())
            ctx = logging.WithContext(ctx, logger)

            // Initialize database
            db, err := database.New(ctx, cfg.Storage.Database)
            if err != nil {
                return fmt.Errorf("failed to connect to database: %w", err)
            }
            defer db.Close()

            logger.Info("connected to database")

            // TODO: Initialize and start servers (SMTP, IMAP, API)
            // This will be implemented in subsequent phases

            // Wait for shutdown signal
            sigCh := make(chan os.Signal, 1)
            signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

            <-sigCh
            logger.Info("shutting down")
            cancel()

            return nil
        },
    }
}

func migrateCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "migrate",
        Short: "Run database migrations",
        RunE: func(cmd *cobra.Command, args []string) error {
            cfg, err := config.Load(cfgFile)
            if err != nil {
                return fmt.Errorf("failed to load config: %w", err)
            }

            logger := logging.New(cfg.Logging)
            ctx := logging.WithContext(context.Background(), logger)

            db, err := database.New(ctx, cfg.Storage.Database)
            if err != nil {
                return fmt.Errorf("failed to connect to database: %w", err)
            }
            defer db.Close()

            logger.Info("running migrations")
            if err := db.Migrate(ctx); err != nil {
                return fmt.Errorf("migration failed: %w", err)
            }

            logger.Info("migrations completed successfully")
            return nil
        },
    }
}

func versionCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "version",
        Short: "Print version information",
        Run: func(cmd *cobra.Command, args []string) {
            fmt.Printf("ESP Server %s\n", version.Version)
            fmt.Printf("Commit: %s\n", version.Commit)
            fmt.Printf("Built: %s\n", version.BuildTime)
        },
    }
}
```

### 7. Version Package

**File**: `internal/version/version.go`

```go
package version

// These variables are set at build time via ldflags
var (
    Version   = "dev"
    Commit    = "unknown"
    BuildTime = "unknown"
)
```

### 8. Makefile

```makefile
.PHONY: build test lint clean migrate run

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X github.com/mnohosten/esp/internal/version.Version=$(VERSION) \
                     -X github.com/mnohosten/esp/internal/version.Commit=$(COMMIT) \
                     -X github.com/mnohosten/esp/internal/version.BuildTime=$(BUILD_TIME)"

# Build the server
build:
	go build $(LDFLAGS) -o bin/esp-server ./cmd/esp-server
	go build $(LDFLAGS) -o bin/esp-cli ./cmd/esp-cli

# Run tests
test:
	go test -v -race ./...

# Run linter
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -rf bin/

# Run database migrations
migrate:
	./bin/esp-server migrate -c configs/server.yaml

# Run the server
run: build
	./bin/esp-server serve -c configs/server.yaml

# Development: run with hot reload (requires air)
dev:
	air -c .air.toml

# Generate (mock, etc.)
generate:
	go generate ./...

# Tidy dependencies
tidy:
	go mod tidy
```

### 9. Example Configuration

**File**: `configs/server.yaml.example`

```yaml
# ESP Server Configuration

server:
  smtp:
    enabled: true
    listen_addr: ":25"
    submission_addr: ":587"
    implicit_tls_addr: ":465"
    hostname: "mail.example.com"
    max_message_size: 26214400  # 25MB
    max_recipients: 100
    read_timeout: 60s
    write_timeout: 60s
    require_tls: false

  imap:
    enabled: true
    listen_addr: ":143"
    implicit_tls_addr: ":993"
    read_timeout: 30m
    write_timeout: 60s

  api:
    enabled: true
    listen_addr: ":8080"
    jwt_secret: "change-me-in-production"
    jwt_expiry: 24h
    rate_limit: 100
    enable_cors: true
    cors_origins:
      - "http://localhost:3000"

storage:
  database:
    host: localhost
    port: 5432
    user: esp
    password: esp_password
    database: esp
    ssl_mode: prefer
    max_connections: 25
    max_idle_conns: 5
    conn_max_lifetime: 1h

  maildir:
    base_path: /var/mail/esp

security:
  tls:
    cert_file: ""
    key_file: ""
    auto_tls: false
    acme_email: ""
    acme_dir: "/var/lib/esp/certs"
    acme_staging: true

logging:
  level: info
  format: json
  output: stdout
  add_source: false
```

## Testing

### Unit Tests

Create test files alongside implementation:
- `internal/config/config_test.go`
- `internal/database/postgres_test.go`
- `internal/logging/logger_test.go`

### Integration Tests

Database tests require a running PostgreSQL instance:
```bash
docker run -d --name esp-postgres -e POSTGRES_USER=esp -e POSTGRES_PASSWORD=test -e POSTGRES_DB=esp -p 5432:5432 postgres:14
```

## Completion Criteria

- [ ] All directory structure created
- [ ] Go module initialized with dependencies
- [ ] Configuration loads from YAML and env vars
- [ ] PostgreSQL connects and runs migrations
- [ ] Structured logging works
- [ ] CLI starts and runs basic commands
- [ ] Makefile builds project
- [ ] All tests pass

## Next Phase

Once Phase 1 is complete, proceed to [Phase 2: SMTP Server](./phase-02-smtp.md).
