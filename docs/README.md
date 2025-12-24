# ESP Documentation

Welcome to the ESP (Email Service Platform) documentation.

## Overview

ESP is a comprehensive email server solution implemented in Go, designed to provide enterprise-grade email capabilities with modern architecture and extensibility.

## Documentation Structure

### Architecture
- [Architecture Overview](./architecture.md) - System design and component interactions

### Development Phases
Detailed implementation guides for each development phase:

| Phase | Document | Description |
|-------|----------|-------------|
| 1 | [Foundation](./phases/phase-01-foundation.md) | Project setup, config, database, logging |
| 2 | [SMTP Server](./phases/phase-02-smtp.md) | SMTP implementation with TLS |
| 3 | [Storage](./phases/phase-03-storage.md) | Maildir and PostgreSQL storage |
| 4 | [IMAP Server](./phases/phase-04-imap.md) | IMAP4rev1 implementation |
| 5 | [Filters](./phases/phase-05-filters.md) | Filter pipeline and integrations |
| 6 | [REST API](./phases/phase-06-api.md) | Management API |
| 7 | [Events](./phases/phase-07-events.md) | Event system and webhooks |
| 8 | [Certificates](./phases/phase-08-certificates.md) | TLS certificate management |
| 9 | [LLM Integration](./phases/phase-09-llm.md) | AI-powered categorization |
| 10 | [Production](./phases/phase-10-production.md) | Testing and deployment |

### Configuration
- [Configuration Reference](./configuration.md) - All configuration options

### API Documentation
- [API Overview](./api/README.md) - REST API documentation
- [OpenAPI Spec](./api/openapi.yaml) - OpenAPI/Swagger specification

### Deployment
- [Docker](./deployment/docker.md) - Docker deployment guide
- [Kubernetes](./deployment/kubernetes.md) - Kubernetes deployment
- [Bare Metal](./deployment/bare-metal.md) - Traditional server deployment

### Development
- [Contributing](./development/contributing.md) - Contribution guidelines
- [Testing](./development/testing.md) - Testing guide
- [Plugins](./development/plugins.md) - Plugin development guide

## Quick Links

- [Project README](../README.md)
- [Current Tasks](../TODO.md)
- [Changelog](../CHANGELOG.md)

## Getting Started

1. Review the [Architecture Overview](./architecture.md)
2. Follow [Phase 1](./phases/phase-01-foundation.md) for project setup
3. Progress through phases sequentially
4. Reference configuration and API docs as needed
