# ESP - Email Service Platform

A comprehensive email solution implemented in Go, providing enterprise-grade email server capabilities.

**Status**: All 10 development phases complete (210/210 tasks) - Ready for deployment

## Features

- **Full SMTP Server** - Supports plain, STARTTLS, and implicit TLS connections
- **Full IMAP Server** - Complete IMAP4rev1 implementation with IDLE support
- **Event-Driven Architecture** - Webhooks and event notifications for integration
- **REST API** - Comprehensive management API for domains, users, mailboxes
- **Security Integrations** - Rspamd spam filtering, ClamAV virus scanning
- **Multi-Domain Hosting** - Host unlimited domains with per-domain configuration
- **Automatic TLS** - Let's Encrypt and ZeroSSL certificate automation
- **LLM Integration** - Email categorization with OpenAI, Anthropic Claude, or Ollama
- **Extensible Filters** - Plugin system for custom mail processing

## Quick Start

```bash
# Build the server
make build

# Run with configuration file
./bin/esp-server --config configs/server.yaml

# Or use Docker
docker-compose up -d
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ESP Server                               │
├─────────────┬─────────────┬─────────────┬───────────────────┤
│ SMTP Server │ IMAP Server │  REST API   │ Certificate Mgr   │
├─────────────┴─────────────┴─────────────┴───────────────────┤
│                    Filter Pipeline                           │
│  (Rspamd → ClamAV → Rate Limit → LLM Categorizer → Custom)  │
├─────────────────────────────────────────────────────────────┤
│                     Event Bus                                │
│         (Webhooks, Audit Logging, Notifications)            │
├─────────────────────────────────────────────────────────────┤
│                    Storage Layer                             │
│              (PostgreSQL + Maildir)                          │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

- [Architecture Overview](./docs/architecture.md)
- [Configuration Reference](./docs/configuration.md)
- [API Documentation](./docs/api/)
- [Deployment Guide](./docs/deployment/)
- [Development Guide](./docs/development/)

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| [Phase 1](./docs/phases/phase-01-foundation.md) | Complete | Foundation & Core Infrastructure |
| [Phase 2](./docs/phases/phase-02-smtp.md) | Complete | SMTP Server Implementation |
| [Phase 3](./docs/phases/phase-03-storage.md) | Complete | Storage Layer |
| [Phase 4](./docs/phases/phase-04-imap.md) | Complete | IMAP Server Implementation |
| [Phase 5](./docs/phases/phase-05-filters.md) | Complete | Filter Pipeline |
| [Phase 6](./docs/phases/phase-06-api.md) | Complete | REST API |
| [Phase 7](./docs/phases/phase-07-events.md) | Complete | Event System |
| [Phase 8](./docs/phases/phase-08-certificates.md) | Complete | Certificate Management |
| [Phase 9](./docs/phases/phase-09-llm.md) | Complete | LLM Integration |
| [Phase 10](./docs/phases/phase-10-production.md) | Complete | Production Readiness |

## Project Structure

```
esp-solution/
├── cmd/
│   ├── esp-server/          # Main server binary
│   └── esp-cli/             # CLI management tool
├── internal/
│   ├── api/                 # REST API server
│   ├── cert/                # Certificate management (ACME/Let's Encrypt)
│   ├── config/              # Configuration system
│   ├── database/            # Database layer with migrations
│   ├── event/               # Event bus and webhooks
│   ├── filter/              # Filter pipeline (Rspamd, ClamAV, rate limiting)
│   ├── imap/                # IMAP server
│   ├── llm/                 # LLM clients (OpenAI, Anthropic, Ollama)
│   ├── logging/             # Structured logging
│   ├── mailbox/             # Mailbox and message management
│   ├── queue/               # Outbound email queue
│   ├── smtp/                # SMTP server
│   ├── storage/             # Maildir storage implementation
│   ├── tls/                 # TLS configuration
│   └── version/             # Version information
├── configs/                 # Configuration files and Grafana dashboards
├── docs/                    # Documentation
├── helm/                    # Kubernetes Helm chart
├── .github/workflows/       # CI/CD pipelines
├── Dockerfile               # Container image
├── docker-compose.yml       # Local development stack
├── go.mod
├── TODO.md                  # Implementation tracker
└── CHANGELOG.md             # Implementation history
```

## Requirements

- Go 1.21+
- PostgreSQL 14+
- (Optional) Rspamd for spam filtering
- (Optional) ClamAV for virus scanning

## License

MIT License - See [LICENSE](./LICENSE) for details.

## Contributing

See [Contributing Guide](./docs/development/contributing.md) for development setup and guidelines.
