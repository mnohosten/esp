# Phase 10: Production Readiness

## Overview

**Goal**: Prepare ESP for production deployment with comprehensive testing, documentation, and deployment configurations.

**Dependencies**: All previous phases

**Estimated Complexity**: Medium

## Prerequisites

- Phases 1-9 completed
- All core functionality working
- Basic tests passing

## Deliverables

1. Comprehensive test suite (>80% coverage)
2. API documentation (OpenAPI)
3. User documentation
4. Docker configuration
5. Kubernetes manifests
6. CI/CD pipeline
7. Monitoring dashboards
8. Operational runbooks

## Test Suite

### 1. Unit Tests

**Coverage Target**: 80%+ for core packages

```go
// internal/config/config_test.go
func TestConfigLoad(t *testing.T)
func TestConfigValidation(t *testing.T)
func TestConfigDefaults(t *testing.T)

// internal/smtp/session_test.go
func TestSMTPSession_Auth(t *testing.T)
func TestSMTPSession_Mail(t *testing.T)
func TestSMTPSession_Rcpt(t *testing.T)
func TestSMTPSession_Data(t *testing.T)

// internal/imap/session_test.go
func TestIMAPSession_Login(t *testing.T)
func TestIMAPSession_Select(t *testing.T)
func TestIMAPSession_Fetch(t *testing.T)
func TestIMAPSession_Search(t *testing.T)

// internal/filter/chain_test.go
func TestFilterChain_Process(t *testing.T)
func TestFilterChain_Order(t *testing.T)
func TestFilterChain_ErrorHandling(t *testing.T)

// internal/event/bus_test.go
func TestEventBus_Publish(t *testing.T)
func TestEventBus_Subscribe(t *testing.T)
func TestEventBus_Wildcard(t *testing.T)
```

### 2. Integration Tests

```go
// tests/integration/smtp_test.go
func TestSMTPDelivery(t *testing.T)
func TestSMTPAuth(t *testing.T)
func TestSMTPTLS(t *testing.T)
func TestSMTPRateLimiting(t *testing.T)

// tests/integration/imap_test.go
func TestIMAPFullWorkflow(t *testing.T)
func TestIMAPIdle(t *testing.T)
func TestIMAPSearch(t *testing.T)

// tests/integration/api_test.go
func TestAPIAuthentication(t *testing.T)
func TestAPIDomainCRUD(t *testing.T)
func TestAPIUserCRUD(t *testing.T)
func TestAPIMessageOperations(t *testing.T)

// tests/integration/filter_test.go
func TestFilterPipeline(t *testing.T)
func TestRspamdIntegration(t *testing.T)
func TestClamAVIntegration(t *testing.T)
```

### 3. End-to-End Tests

```go
// tests/e2e/email_flow_test.go
func TestInboundEmailFlow(t *testing.T) {
    // 1. Send email via SMTP
    // 2. Verify filter processing
    // 3. Check maildir storage
    // 4. Verify IMAP access
    // 5. Check event emission
}

func TestOutboundEmailFlow(t *testing.T) {
    // 1. Submit via SMTP/API
    // 2. Verify queue entry
    // 3. Mock delivery
    // 4. Check events
}

func TestMultiDomainSetup(t *testing.T) {
    // 1. Create multiple domains
    // 2. Create users in each
    // 3. Send cross-domain email
    // 4. Verify isolation
}
```

### 4. Performance Tests

```go
// tests/perf/smtp_bench_test.go
func BenchmarkSMTPDelivery(b *testing.B)
func BenchmarkConcurrentConnections(b *testing.B)

// tests/perf/imap_bench_test.go
func BenchmarkIMAPFetch(b *testing.B)
func BenchmarkIMAPSearch(b *testing.B)

// tests/perf/api_bench_test.go
func BenchmarkAPIRequests(b *testing.B)
```

## Documentation

### 1. API Documentation

**File**: `docs/api/openapi.yaml`

```yaml
openapi: 3.0.3
info:
  title: ESP - Email Service Platform API
  version: 1.0.0
  description: REST API for managing the ESP email server

servers:
  - url: http://localhost:8080/api/v1
    description: Local development

security:
  - bearerAuth: []

paths:
  /auth/login:
    post:
      summary: Authenticate user
      tags: [Authentication]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Successful authentication
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'

  /domains:
    get:
      summary: List all domains
      tags: [Domains]
      responses:
        '200':
          description: List of domains
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Domain'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    LoginRequest:
      type: object
      required: [email, password]
      properties:
        email:
          type: string
          format: email
        password:
          type: string
          format: password

    Domain:
      type: object
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
        enabled:
          type: boolean
```

### 2. Configuration Reference

**File**: `docs/configuration.md`

Complete reference of all configuration options with examples.

### 3. Deployment Guides

**Files**:
- `docs/deployment/docker.md`
- `docs/deployment/kubernetes.md`
- `docs/deployment/bare-metal.md`

## Docker Configuration

### Dockerfile

**File**: `Dockerfile`

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /esp-server ./cmd/esp-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /esp-cli ./cmd/esp-cli

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /esp-server /usr/local/bin/
COPY --from=builder /esp-cli /usr/local/bin/

# Create non-root user
RUN addgroup -S esp && adduser -S esp -G esp

# Create data directories
RUN mkdir -p /var/mail/esp /var/lib/esp/certs /etc/esp \
    && chown -R esp:esp /var/mail/esp /var/lib/esp /etc/esp

USER esp

EXPOSE 25 465 587 143 993 8080

VOLUME ["/var/mail/esp", "/var/lib/esp", "/etc/esp"]

ENTRYPOINT ["esp-server"]
CMD ["serve", "--config", "/etc/esp/server.yaml"]
```

### Docker Compose

**File**: `docker-compose.yml`

```yaml
version: '3.8'

services:
  esp:
    build: .
    container_name: esp-server
    ports:
      - "25:25"
      - "465:465"
      - "587:587"
      - "143:143"
      - "993:993"
      - "8080:8080"
    volumes:
      - esp-mail:/var/mail/esp
      - esp-data:/var/lib/esp
      - ./configs/server.yaml:/etc/esp/server.yaml:ro
    environment:
      - ESP_STORAGE_DATABASE_HOST=postgres
      - ESP_STORAGE_DATABASE_PASSWORD=${DB_PASSWORD}
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - esp-network
    restart: unless-stopped

  postgres:
    image: postgres:14-alpine
    container_name: esp-postgres
    environment:
      POSTGRES_USER: esp
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: esp
    volumes:
      - esp-postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U esp"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - esp-network
    restart: unless-stopped

  rspamd:
    image: rspamd/rspamd:latest
    container_name: esp-rspamd
    volumes:
      - esp-rspamd:/var/lib/rspamd
    networks:
      - esp-network
    restart: unless-stopped

  clamav:
    image: clamav/clamav:latest
    container_name: esp-clamav
    volumes:
      - esp-clamav:/var/lib/clamav
    networks:
      - esp-network
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: esp-prometheus
    volumes:
      - ./configs/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - esp-prometheus:/prometheus
    networks:
      - esp-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: esp-grafana
    ports:
      - "3000:3000"
    volumes:
      - esp-grafana:/var/lib/grafana
      - ./configs/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    networks:
      - esp-network
    restart: unless-stopped

volumes:
  esp-mail:
  esp-data:
  esp-postgres:
  esp-rspamd:
  esp-clamav:
  esp-prometheus:
  esp-grafana:

networks:
  esp-network:
    driver: bridge
```

## Kubernetes Configuration

### Helm Chart Structure

```
helm/esp/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── pvc.yaml
│   ├── ingress.yaml
│   └── hpa.yaml
```

### Deployment

**File**: `helm/esp/templates/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "esp.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ include "esp.name" . }}
  template:
    metadata:
      labels:
        app: {{ include "esp.name" . }}
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      containers:
        - name: esp
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          ports:
            - name: smtp
              containerPort: 25
            - name: smtps
              containerPort: 465
            - name: submission
              containerPort: 587
            - name: imap
              containerPort: 143
            - name: imaps
              containerPort: 993
            - name: api
              containerPort: 8080
          volumeMounts:
            - name: config
              mountPath: /etc/esp
            - name: mail
              mountPath: /var/mail/esp
            - name: certs
              mountPath: /var/lib/esp/certs
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          livenessProbe:
            httpGet:
              path: /health
              port: api
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: api
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: {{ include "esp.fullname" . }}-config
        - name: mail
          persistentVolumeClaim:
            claimName: {{ include "esp.fullname" . }}-mail
        - name: certs
          persistentVolumeClaim:
            claimName: {{ include "esp.fullname" . }}-certs
```

## CI/CD Pipeline

### GitHub Actions

**File**: `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_USER: esp
          POSTGRES_PASSWORD: test
          POSTGRES_DB: esp_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install dependencies
        run: go mod download

      - name: Run linter
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest

      - name: Run tests
        run: go test -v -race -coverprofile=coverage.txt ./...
        env:
          ESP_TEST_DB_HOST: localhost
          ESP_TEST_DB_USER: esp
          ESP_TEST_DB_PASSWORD: test
          ESP_TEST_DB_NAME: esp_test

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: coverage.txt

  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          tags: esp:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  release:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Login to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            mnohosten/esp:latest
            mnohosten/esp:${{ github.sha }}
```

## Monitoring

### Prometheus Configuration

**File**: `configs/prometheus.yml`

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'esp'
    static_configs:
      - targets: ['esp:8080']
```

### Grafana Dashboard

**File**: `configs/grafana/dashboards/esp.json`

Dashboard with panels for:
- Messages received/sent/bounced
- Queue size and processing rate
- Active SMTP/IMAP connections
- API request rate and latency
- Error rates
- Resource usage

## Operational Runbooks

### Runbook: High Queue Backlog

**File**: `docs/runbooks/high-queue-backlog.md`

```markdown
# High Queue Backlog

## Symptoms
- Queue size growing
- Delivery delays reported
- Alert: queue.stuck event

## Investigation
1. Check queue status: `esp-cli queue status`
2. Check delivery worker logs
3. Check target MX availability
4. Check rate limiting status

## Resolution
1. If MX is down: Wait or configure backup MX
2. If rate limited: Adjust limits or wait
3. If worker crash: Restart workers
4. If disk full: Clear old logs/data

## Prevention
- Monitor queue size
- Set up alerts for queue growth
- Implement circuit breakers
```

## Task Breakdown

### Testing
- [ ] Write unit tests for all packages
- [ ] Write integration tests
- [ ] Write E2E tests
- [ ] Write performance benchmarks
- [ ] Achieve 80%+ code coverage

### Documentation
- [ ] Complete OpenAPI spec
- [ ] Write configuration reference
- [ ] Write deployment guides
- [ ] Create architecture diagrams
- [ ] Write runbooks

### Docker
- [ ] Create optimized Dockerfile
- [ ] Create docker-compose.yml
- [ ] Test multi-container setup

### Kubernetes
- [ ] Create Helm chart
- [ ] Test Kubernetes deployment
- [ ] Configure HPA
- [ ] Set up monitoring

### CI/CD
- [ ] Set up GitHub Actions
- [ ] Configure automated testing
- [ ] Configure Docker builds
- [ ] Set up release automation

### Monitoring
- [ ] Configure Prometheus metrics
- [ ] Create Grafana dashboards
- [ ] Set up alerting rules
- [ ] Create status page

### Security
- [ ] Security audit
- [ ] Dependency scanning
- [ ] SAST/DAST integration
- [ ] Document security practices

## Completion Criteria

- [ ] Test coverage > 80%
- [ ] All documentation complete
- [ ] Docker builds and runs
- [ ] Kubernetes deploys successfully
- [ ] CI/CD pipeline works
- [ ] Monitoring dashboards ready
- [ ] Runbooks documented
- [ ] Security review passed

## Project Complete!

Once Phase 10 is complete, ESP is ready for production deployment.

### Post-Launch Tasks
- [ ] Set up production monitoring
- [ ] Configure alerting
- [ ] Document on-call procedures
- [ ] Plan feature roadmap
