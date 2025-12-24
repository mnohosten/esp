# ESP Configuration Reference

This document provides a comprehensive reference for all ESP configuration options.

## Configuration Sources

ESP supports configuration from multiple sources (in order of precedence):

1. Command-line flags
2. Environment variables (prefixed with `ESP_`)
3. Configuration file (`server.yaml`)
4. Default values

## Configuration File Location

Default locations (checked in order):
- `./server.yaml`
- `./configs/server.yaml`
- `/etc/esp/server.yaml`
- `$HOME/.esp/server.yaml`

Override with: `--config /path/to/config.yaml`

## Configuration Sections

### Server

General server settings.

```yaml
server:
  # Server hostname (used in SMTP greetings)
  hostname: mail.example.com

  # Log level: debug, info, warn, error
  log_level: info

  # Log format: json, text
  log_format: json
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `hostname` | `ESP_SERVER_HOSTNAME` | `localhost` | Server hostname |
| `log_level` | `ESP_SERVER_LOG_LEVEL` | `info` | Logging level |
| `log_format` | `ESP_SERVER_LOG_FORMAT` | `json` | Log output format |

### SMTP

SMTP server configuration.

```yaml
smtp:
  # Enable SMTP server
  enabled: true

  # Plain SMTP port
  port: 25

  # SMTP over TLS (implicit)
  tls_port: 465

  # Submission port (STARTTLS)
  submission_port: 587

  # Maximum message size in bytes
  max_message_size: 26214400  # 25MB

  # Maximum recipients per message
  max_recipients: 100

  # Connection limits
  max_connections: 1000

  # Timeout settings
  read_timeout: 60s
  write_timeout: 60s

  # Require authentication for submission
  require_auth: true

  # Allowed authentication mechanisms
  auth_mechanisms:
    - PLAIN
    - LOGIN
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `enabled` | `ESP_SMTP_ENABLED` | `true` | Enable SMTP |
| `port` | `ESP_SMTP_PORT` | `25` | SMTP port |
| `tls_port` | `ESP_SMTP_TLS_PORT` | `465` | SMTPS port |
| `submission_port` | `ESP_SMTP_SUBMISSION_PORT` | `587` | Submission port |
| `max_message_size` | `ESP_SMTP_MAX_MESSAGE_SIZE` | `26214400` | Max message size |
| `max_recipients` | `ESP_SMTP_MAX_RECIPIENTS` | `100` | Max recipients |

### IMAP

IMAP server configuration.

```yaml
imap:
  # Enable IMAP server
  enabled: true

  # Plain IMAP port
  port: 143

  # IMAP over TLS (implicit)
  tls_port: 993

  # Connection limits
  max_connections: 1000

  # Idle timeout
  idle_timeout: 30m

  # Enable IDLE extension
  idle_enabled: true
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `enabled` | `ESP_IMAP_ENABLED` | `true` | Enable IMAP |
| `port` | `ESP_IMAP_PORT` | `143` | IMAP port |
| `tls_port` | `ESP_IMAP_TLS_PORT` | `993` | IMAPS port |
| `idle_timeout` | `ESP_IMAP_IDLE_TIMEOUT` | `30m` | IDLE timeout |

### API

REST API configuration.

```yaml
api:
  # Enable REST API
  enabled: true

  # API port
  port: 8080

  # API bind address
  address: 0.0.0.0

  # JWT settings
  jwt_secret: your-secret-key
  jwt_expiry: 24h
  jwt_refresh_expiry: 168h  # 7 days

  # Rate limiting
  rate_limit: 100
  rate_limit_window: 1m

  # CORS settings
  cors_enabled: true
  cors_origins:
    - "*"
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `enabled` | `ESP_API_ENABLED` | `true` | Enable API |
| `port` | `ESP_API_PORT` | `8080` | API port |
| `jwt_secret` | `ESP_API_JWT_SECRET` | - | JWT signing secret |
| `jwt_expiry` | `ESP_API_JWT_EXPIRY` | `24h` | Token expiry |

### Storage

Database and maildir configuration.

```yaml
storage:
  # Maildir storage
  maildir:
    path: /var/mail/esp

  # Database connection
  database:
    driver: postgres
    host: localhost
    port: 5432
    name: esp
    user: esp
    password: secret
    sslmode: prefer
    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime: 5m
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `maildir.path` | `ESP_STORAGE_MAILDIR_PATH` | `/var/mail/esp` | Maildir path |
| `database.host` | `ESP_STORAGE_DATABASE_HOST` | `localhost` | DB host |
| `database.port` | `ESP_STORAGE_DATABASE_PORT` | `5432` | DB port |
| `database.name` | `ESP_STORAGE_DATABASE_NAME` | `esp` | DB name |
| `database.user` | `ESP_STORAGE_DATABASE_USER` | `esp` | DB user |
| `database.password` | `ESP_STORAGE_DATABASE_PASSWORD` | - | DB password |
| `database.sslmode` | `ESP_STORAGE_DATABASE_SSLMODE` | `prefer` | SSL mode |

### TLS

TLS/SSL certificate configuration.

```yaml
tls:
  # Certificate mode: manual, acme
  mode: acme

  # Manual certificate paths
  cert_file: /etc/esp/certs/cert.pem
  key_file: /etc/esp/certs/key.pem

  # ACME (Let's Encrypt) settings
  acme:
    enabled: true
    email: admin@example.com
    directory: https://acme-v02.api.letsencrypt.org/directory
    cache_dir: /var/lib/esp/certs
    domains:
      - mail.example.com
      - smtp.example.com
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `mode` | `ESP_TLS_MODE` | `manual` | Certificate mode |
| `cert_file` | `ESP_TLS_CERT_FILE` | - | Certificate path |
| `key_file` | `ESP_TLS_KEY_FILE` | - | Key path |
| `acme.enabled` | `ESP_TLS_ACME_ENABLED` | `false` | Enable ACME |
| `acme.email` | `ESP_TLS_ACME_EMAIL` | - | ACME account email |

### Filters

Email filter configuration.

```yaml
filters:
  # Rspamd spam filter
  rspamd:
    enabled: true
    url: http://localhost:11333
    password: ""
    timeout: 30s
    reject_threshold: 15.0
    quarantine_threshold: 6.0

  # ClamAV antivirus
  clamav:
    enabled: true
    address: localhost:3310
    network: tcp  # tcp or unix
    timeout: 60s

  # Rate limiting
  ratelimit:
    enabled: true
    per_ip: 100
    per_sender: 50
    per_recipient: 200
    window: 1h
```

| Option | Env Var | Description |
|--------|---------|-------------|
| `rspamd.enabled` | `ESP_FILTERS_RSPAMD_ENABLED` | Enable Rspamd |
| `rspamd.url` | `ESP_FILTERS_RSPAMD_URL` | Rspamd URL |
| `clamav.enabled` | `ESP_FILTERS_CLAMAV_ENABLED` | Enable ClamAV |
| `clamav.address` | `ESP_FILTERS_CLAMAV_ADDRESS` | ClamAV address |

### LLM

LLM integration for email categorization.

```yaml
llm:
  # Enable LLM categorization
  enabled: false

  # Provider: openai, anthropic, ollama
  provider: ollama

  # Model name
  model: llama3.2

  # Timeout for LLM requests
  timeout: 60s

  # Minimum confidence for categorization
  min_confidence: 0.7

  # OpenAI settings
  openai:
    api_key: sk-...
    org_id: ""
    base_url: ""  # For Azure OpenAI

  # Anthropic settings
  anthropic:
    api_key: sk-ant-...

  # Ollama settings
  ollama:
    endpoint: http://localhost:11434

  # Custom categories
  categories:
    - name: primary
      description: Important emails requiring attention
      folder: INBOX
    - name: promotions
      description: Marketing and promotional emails
      folder: Promotions
```

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `enabled` | `ESP_LLM_ENABLED` | `false` | Enable LLM |
| `provider` | `ESP_LLM_PROVIDER` | `ollama` | LLM provider |
| `model` | `ESP_LLM_MODEL` | `llama3.2` | Model name |

### Queue

Outbound queue configuration.

```yaml
queue:
  # Queue directory
  path: /var/lib/esp/queue

  # Number of delivery workers
  workers: 10

  # Retry intervals
  retry_intervals:
    - 5m
    - 15m
    - 30m
    - 1h
    - 2h
    - 4h
    - 8h
    - 16h
    - 24h

  # Maximum delivery attempts
  max_attempts: 10

  # Bounce handling
  bounce_address: postmaster@example.com
```

### Events

Event system configuration.

```yaml
events:
  # Event queue size
  queue_size: 10000

  # Number of event workers
  workers: 5

  # Webhooks
  webhooks:
    - url: https://example.com/webhook
      events:
        - message.received
        - message.sent
      secret: webhook-secret
      timeout: 30s
      retry_count: 3
```

## Environment Variable Mapping

All configuration options can be set via environment variables using this pattern:

```
ESP_<SECTION>_<OPTION>=value
```

Nested options use underscores:
```
ESP_STORAGE_DATABASE_HOST=localhost
ESP_FILTERS_RSPAMD_ENABLED=true
```

## Example Configuration

Complete example configuration file:

```yaml
server:
  hostname: mail.example.com
  log_level: info
  log_format: json

smtp:
  enabled: true
  port: 25
  tls_port: 465
  submission_port: 587
  max_message_size: 26214400
  require_auth: true

imap:
  enabled: true
  port: 143
  tls_port: 993
  idle_timeout: 30m

api:
  enabled: true
  port: 8080
  jwt_secret: ${ESP_API_JWT_SECRET}
  cors_enabled: true

storage:
  maildir:
    path: /var/mail/esp
  database:
    host: ${ESP_STORAGE_DATABASE_HOST}
    port: 5432
    name: esp
    user: esp
    password: ${ESP_STORAGE_DATABASE_PASSWORD}
    sslmode: prefer

tls:
  mode: acme
  acme:
    enabled: true
    email: admin@example.com
    domains:
      - mail.example.com

filters:
  rspamd:
    enabled: true
    url: http://rspamd:11333
  clamav:
    enabled: true
    address: clamav:3310
  ratelimit:
    enabled: true
    per_ip: 100

llm:
  enabled: false
  provider: ollama
  model: llama3.2
```
