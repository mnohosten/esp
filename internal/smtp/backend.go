package smtp

import (
	"log/slog"

	"github.com/emersion/go-smtp"
	"github.com/mnohosten/esp/internal/config"
)

// Backend implements smtp.Backend for ESP.
type Backend struct {
	config        config.SMTPConfig
	logger        *slog.Logger
	authenticator *Authenticator

	// TODO: Add these dependencies as they are implemented:
	// domains     *domain.Manager
	// users       *user.Store
	// queue       *queue.Manager
	// filterChain *filter.Chain
	// eventBus    *event.Bus
}

// BackendOption is a functional option for configuring the Backend.
type BackendOption func(*Backend)

// WithAuthenticator sets the authenticator for the backend.
func WithAuthenticator(auth *Authenticator) BackendOption {
	return func(b *Backend) {
		b.authenticator = auth
	}
}

// NewBackend creates a new SMTP backend.
func NewBackend(cfg config.SMTPConfig, logger *slog.Logger, opts ...BackendOption) *Backend {
	b := &Backend{
		config: cfg,
		logger: logger.With("component", "smtp.backend"),
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

// NewSession creates a new SMTP session for the given connection.
// This implements the smtp.Backend interface.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remoteAddr := c.Conn().RemoteAddr().String()
	hostname := c.Hostname()

	b.logger.Debug("new SMTP session",
		"remote_addr", remoteAddr,
		"client_hostname", hostname,
	)

	return newSession(b, c), nil
}

// Config returns the SMTP configuration.
func (b *Backend) Config() config.SMTPConfig {
	return b.config
}

// Logger returns the backend's logger.
func (b *Backend) Logger() *slog.Logger {
	return b.logger
}

// Authenticator returns the authenticator, or nil if not configured.
func (b *Backend) Authenticator() *Authenticator {
	return b.authenticator
}
