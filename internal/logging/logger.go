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
	} else if cfg.Output == "stderr" {
		output = os.Stderr
	} else {
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Fall back to stdout on error
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

// FromContext returns the logger from context, or the default logger
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

// WithComponent returns a logger with a component name
func WithComponent(logger *slog.Logger, component string) *slog.Logger {
	return logger.With("component", component)
}

// WithRequestID returns a logger with a request ID
func WithRequestID(logger *slog.Logger, requestID string) *slog.Logger {
	return logger.With("request_id", requestID)
}

// WithUserID returns a logger with a user ID
func WithUserID(logger *slog.Logger, userID string) *slog.Logger {
	return logger.With("user_id", userID)
}

// WithDomain returns a logger with a domain name
func WithDomain(logger *slog.Logger, domain string) *slog.Logger {
	return logger.With("domain", domain)
}
