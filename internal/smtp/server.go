// Package smtp implements the SMTP server for ESP.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/mnohosten/esp/internal/config"
)

// Server wraps the go-smtp server with ESP configuration.
type Server struct {
	config    config.SMTPConfig
	tlsConfig *tls.Config
	logger    *slog.Logger
	backend   smtp.Backend

	// Listeners for different ports
	smtpListener       net.Listener
	submissionListener net.Listener
	implicitTLSListener net.Listener

	// Servers for each listener
	smtpServer       *smtp.Server
	submissionServer *smtp.Server
	implicitTLSServer *smtp.Server

	mu      sync.Mutex
	running bool
}

// New creates a new SMTP server.
func New(cfg config.SMTPConfig, backend smtp.Backend, tlsConfig *tls.Config, logger *slog.Logger) *Server {
	return &Server{
		config:    cfg,
		backend:   backend,
		tlsConfig: tlsConfig,
		logger:    logger.With("component", "smtp"),
	}
}

// createServer creates a configured go-smtp server instance.
// The requireAuth parameter is stored for reference but authentication
// is ultimately controlled by the Backend implementation.
func (s *Server) createServer(requireAuth bool, implicitTLS bool) *smtp.Server {
	srv := smtp.NewServer(s.backend)

	srv.Domain = s.config.Hostname
	srv.ReadTimeout = s.config.ReadTimeout
	srv.WriteTimeout = s.config.WriteTimeout
	srv.MaxMessageBytes = s.config.MaxMessageSize
	srv.MaxRecipients = s.config.MaxRecipients
	srv.AllowInsecureAuth = !s.config.RequireTLS && !implicitTLS

	// Enable STARTTLS if we have TLS config and not implicit TLS
	if s.tlsConfig != nil && !implicitTLS {
		srv.TLSConfig = s.tlsConfig
		srv.EnableSMTPUTF8 = true
	}

	return srv
}

// Start starts all SMTP listeners based on configuration.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("server already running")
	}

	var errs []error

	// Start main SMTP listener (port 25) - no auth required
	if s.config.ListenAddr != "" {
		if err := s.startSMTPListener(); err != nil {
			errs = append(errs, fmt.Errorf("smtp listener: %w", err))
		}
	}

	// Start submission listener (port 587) - auth required, STARTTLS
	if s.config.SubmissionAddr != "" {
		if err := s.startSubmissionListener(); err != nil {
			errs = append(errs, fmt.Errorf("submission listener: %w", err))
		}
	}

	// Start implicit TLS listener (port 465)
	if s.config.ImplicitTLSAddr != "" && s.tlsConfig != nil {
		if err := s.startImplicitTLSListener(); err != nil {
			errs = append(errs, fmt.Errorf("implicit tls listener: %w", err))
		}
	}

	if len(errs) > 0 {
		// Clean up any started listeners
		s.stopListeners()
		return errors.Join(errs...)
	}

	s.running = true
	s.logger.Info("SMTP server started",
		"smtp_addr", s.config.ListenAddr,
		"submission_addr", s.config.SubmissionAddr,
		"implicit_tls_addr", s.config.ImplicitTLSAddr,
	)

	return nil
}

// startSMTPListener starts the main SMTP listener (typically port 25).
func (s *Server) startSMTPListener() error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}

	s.smtpListener = listener
	s.smtpServer = s.createServer(false, false)

	s.logger.Info("starting SMTP listener", "addr", s.config.ListenAddr)

	go func() {
		if err := s.smtpServer.Serve(listener); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			s.logger.Error("SMTP server error", "error", err)
		}
	}()

	return nil
}

// startSubmissionListener starts the submission listener (typically port 587).
func (s *Server) startSubmissionListener() error {
	listener, err := net.Listen("tcp", s.config.SubmissionAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.SubmissionAddr, err)
	}

	s.submissionListener = listener
	s.submissionServer = s.createServer(true, false) // Auth required

	s.logger.Info("starting submission listener", "addr", s.config.SubmissionAddr)

	go func() {
		if err := s.submissionServer.Serve(listener); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			s.logger.Error("submission server error", "error", err)
		}
	}()

	return nil
}

// startImplicitTLSListener starts the implicit TLS listener (typically port 465).
func (s *Server) startImplicitTLSListener() error {
	listener, err := tls.Listen("tcp", s.config.ImplicitTLSAddr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ImplicitTLSAddr, err)
	}

	s.implicitTLSListener = listener
	s.implicitTLSServer = s.createServer(true, true) // Auth required, implicit TLS

	s.logger.Info("starting implicit TLS listener", "addr", s.config.ImplicitTLSAddr)

	go func() {
		if err := s.implicitTLSServer.Serve(listener); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			s.logger.Error("implicit TLS server error", "error", err)
		}
	}()

	return nil
}

// stopListeners stops all active listeners.
func (s *Server) stopListeners() {
	if s.smtpListener != nil {
		s.smtpListener.Close()
		s.smtpListener = nil
	}
	if s.submissionListener != nil {
		s.submissionListener.Close()
		s.submissionListener = nil
	}
	if s.implicitTLSListener != nil {
		s.implicitTLSListener.Close()
		s.implicitTLSListener = nil
	}
}

// Stop gracefully stops the server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("stopping SMTP server")

	var errs []error

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Close all servers gracefully
	if s.smtpServer != nil {
		if err := s.smtpServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing smtp server: %w", err))
		}
	}
	if s.submissionServer != nil {
		if err := s.submissionServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing submission server: %w", err))
		}
	}
	if s.implicitTLSServer != nil {
		if err := s.implicitTLSServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing implicit tls server: %w", err))
		}
	}

	// Wait for context or timeout
	select {
	case <-shutdownCtx.Done():
		if shutdownCtx.Err() == context.DeadlineExceeded {
			s.logger.Warn("shutdown timed out, forcing close")
		}
	default:
	}

	s.running = false
	s.logger.Info("SMTP server stopped")

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Running returns whether the server is running.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Config returns the server configuration.
func (s *Server) Config() config.SMTPConfig {
	return s.config
}
