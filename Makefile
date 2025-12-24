.PHONY: build test lint clean migrate run dev deps generate help

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X github.com/mnohosten/esp/internal/version.Version=$(VERSION) \
                     -X github.com/mnohosten/esp/internal/version.Commit=$(COMMIT) \
                     -X github.com/mnohosten/esp/internal/version.BuildTime=$(BUILD_TIME)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
SERVER_BINARY=esp-server
CLI_BINARY=esp-cli

# Directories
BIN_DIR=bin
CMD_DIR=cmd

## help: Show this help message
help:
	@echo "ESP - Email Service Platform"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## /  /'

## build: Build all binaries
build: build-server build-cli

## build-server: Build the server binary
build-server:
	@echo "Building $(SERVER_BINARY)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(SERVER_BINARY) ./$(CMD_DIR)/esp-server

## build-cli: Build the CLI binary
build-cli:
	@echo "Building $(CLI_BINARY)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(CLI_BINARY) ./$(CMD_DIR)/esp-cli

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

## deps: Download and tidy dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## migrate: Run database migrations
migrate: build-server
	@echo "Running migrations..."
	./$(BIN_DIR)/$(SERVER_BINARY) migrate -c configs/server.yaml

## migrate-status: Show migration status
migrate-status: build-server
	@echo "Checking migration status..."
	./$(BIN_DIR)/$(SERVER_BINARY) migrate status -c configs/server.yaml

## run: Build and run the server
run: build-server
	@echo "Starting server..."
	./$(BIN_DIR)/$(SERVER_BINARY) serve -c configs/server.yaml

## dev: Run with hot reload (requires air)
dev:
	@if command -v air >/dev/null 2>&1; then \
		air -c .air.toml; \
	else \
		echo "air not installed. Run: go install github.com/cosmtrek/air@latest"; \
		echo "Falling back to regular run..."; \
		$(MAKE) run; \
	fi

## generate: Run go generate
generate:
	@echo "Running go generate..."
	$(GOCMD) generate ./...

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t mnohosten/esp:$(VERSION) .
	docker tag mnohosten/esp:$(VERSION) mnohosten/esp:latest

## docker-run: Run with docker-compose
docker-run:
	docker-compose up -d

## docker-stop: Stop docker-compose
docker-stop:
	docker-compose down

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/cosmtrek/air@latest
	@echo "Tools installed successfully"

## version: Show version information
version: build-server
	./$(BIN_DIR)/$(SERVER_BINARY) version

# Default target
.DEFAULT_GOAL := help
