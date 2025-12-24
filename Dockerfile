# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Download dependencies first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .

# Build with optimizations
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -o /esp-server ./cmd/esp-server

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -o /esp-cli ./cmd/esp-cli

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binaries from builder
COPY --from=builder /esp-server /usr/local/bin/
COPY --from=builder /esp-cli /usr/local/bin/

# Create non-root user
RUN addgroup -S esp && adduser -S esp -G esp

# Create required directories
RUN mkdir -p /var/mail/esp /var/lib/esp/certs /var/lib/esp/queue /etc/esp /var/log/esp \
    && chown -R esp:esp /var/mail/esp /var/lib/esp /etc/esp /var/log/esp

# Copy default configuration
COPY configs/server.yaml.example /etc/esp/server.yaml

# Switch to non-root user
USER esp

# Expose ports
# 25 - SMTP
# 465 - SMTPS
# 587 - Submission
# 143 - IMAP
# 993 - IMAPS
# 8080 - REST API
EXPOSE 25 465 587 143 993 8080

# Volumes for persistent data
VOLUME ["/var/mail/esp", "/var/lib/esp", "/etc/esp"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["esp-server"]
CMD ["serve", "--config", "/etc/esp/server.yaml"]
