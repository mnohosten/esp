package smtp

import (
	"context"
	"log/slog"

	"github.com/emersion/go-smtp"
	"github.com/mnohosten/esp/internal/config"
	"github.com/mnohosten/esp/internal/queue"
)

// LocalDeliverer handles local email delivery.
type LocalDeliverer interface {
	// DeliverLocal delivers a message to a local recipient.
	// Returns true if delivery was successful, false if recipient not found.
	DeliverLocal(ctx context.Context, sender, recipient string, content []byte) (bool, error)
}

// Backend implements smtp.Backend for ESP.
type Backend struct {
	config         config.SMTPConfig
	logger         *slog.Logger
	authenticator  *Authenticator
	queueMgr       *queue.Manager
	queueDir       string
	localDeliverer LocalDeliverer
}

// BackendOption is a functional option for configuring the Backend.
type BackendOption func(*Backend)

// WithAuthenticator sets the authenticator for the backend.
func WithAuthenticator(auth *Authenticator) BackendOption {
	return func(b *Backend) {
		b.authenticator = auth
	}
}

// WithQueueManager sets the queue manager for the backend.
func WithQueueManager(mgr *queue.Manager, queueDir string) BackendOption {
	return func(b *Backend) {
		b.queueMgr = mgr
		b.queueDir = queueDir
	}
}

// WithLocalDeliverer sets the local delivery handler.
func WithLocalDeliverer(ld LocalDeliverer) BackendOption {
	return func(b *Backend) {
		b.localDeliverer = ld
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

// QueueManager returns the queue manager, or nil if not configured.
func (b *Backend) QueueManager() *queue.Manager {
	return b.queueMgr
}

// QueueDir returns the queue directory path.
func (b *Backend) QueueDir() string {
	return b.queueDir
}

// LocalDeliverer returns the local delivery handler, or nil if not configured.
func (b *Backend) LocalDeliverer() LocalDeliverer {
	return b.localDeliverer
}
