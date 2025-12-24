// Package imap implements the IMAP server for ESP.
package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/mnohosten/esp/internal/config"
)

// Server wraps the go-imap server with ESP configuration.
type Server struct {
	config    config.IMAPConfig
	tlsConfig *tls.Config
	logger    *slog.Logger
	backend   *Backend

	// Listeners for different ports
	imapListener        net.Listener
	implicitTLSListener net.Listener

	// Servers for each listener
	imapServer        *imapserver.Server
	implicitTLSServer *imapserver.Server

	mu      sync.Mutex
	running bool
}

// New creates a new IMAP server.
func New(cfg config.IMAPConfig, backend *Backend, tlsConfig *tls.Config, logger *slog.Logger) *Server {
	return &Server{
		config:    cfg,
		backend:   backend,
		tlsConfig: tlsConfig,
		logger:    logger.With("component", "imap"),
	}
}

// createServer creates a configured go-imap server instance.
func (s *Server) createServer() *imapserver.Server {
	// Build capabilities set
	caps := make(imap.CapSet)
	caps[imap.CapIMAP4rev1] = struct{}{}
	caps[imap.CapIMAP4rev2] = struct{}{}

	// Add STARTTLS capability if TLS is configured
	if s.tlsConfig != nil {
		caps[imap.CapStartTLS] = struct{}{}
	}

	// Add supported capabilities
	caps[imap.CapIdle] = struct{}{}
	caps[imap.CapMove] = struct{}{}
	caps[imap.CapUIDPlus] = struct{}{}
	caps[imap.CapLiteralMinus] = struct{}{}
	caps[imap.CapSASLIR] = struct{}{}
	caps[imap.CapNamespace] = struct{}{}
	caps[imap.CapUnselect] = struct{}{}
	caps[imap.CapSort] = struct{}{}
	caps[imap.CapSortDisplay] = struct{}{}
	caps[imap.CapSpecialUse] = struct{}{}
	caps[imap.CapListExtended] = struct{}{}
	caps[imap.CapListStatus] = struct{}{}

	opts := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			session := s.backend.NewSession(conn.NetConn())
			greeting := &imapserver.GreetingData{}
			return session, greeting, nil
		},
		Caps:      caps,
		TLSConfig: s.tlsConfig,
	}

	srv := imapserver.New(opts)

	return srv
}

// Start starts all IMAP listeners based on configuration.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("server already running")
	}

	var errs []error

	// Start main IMAP listener (port 143) - STARTTLS available
	if s.config.ListenAddr != "" {
		if err := s.startIMAPListener(); err != nil {
			errs = append(errs, fmt.Errorf("imap listener: %w", err))
		}
	}

	// Start implicit TLS listener (port 993)
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
	s.logger.Info("IMAP server started",
		"imap_addr", s.config.ListenAddr,
		"implicit_tls_addr", s.config.ImplicitTLSAddr,
	)

	return nil
}

// startIMAPListener starts the main IMAP listener (typically port 143).
func (s *Server) startIMAPListener() error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}

	s.imapListener = listener
	s.imapServer = s.createServer()

	s.logger.Info("starting IMAP listener", "addr", s.config.ListenAddr)

	go func() {
		if err := s.imapServer.Serve(listener); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.Error("IMAP server error", "error", err)
			}
		}
	}()

	return nil
}

// startImplicitTLSListener starts the implicit TLS listener (typically port 993).
func (s *Server) startImplicitTLSListener() error {
	listener, err := tls.Listen("tcp", s.config.ImplicitTLSAddr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ImplicitTLSAddr, err)
	}

	s.implicitTLSListener = listener
	s.implicitTLSServer = s.createServer()

	s.logger.Info("starting implicit TLS listener", "addr", s.config.ImplicitTLSAddr)

	go func() {
		if err := s.implicitTLSServer.Serve(listener); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.Error("implicit TLS server error", "error", err)
			}
		}
	}()

	return nil
}

// stopListeners stops all active listeners.
func (s *Server) stopListeners() {
	if s.imapListener != nil {
		s.imapListener.Close()
		s.imapListener = nil
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

	s.logger.Info("stopping IMAP server")

	// Close all listeners
	s.stopListeners()

	s.running = false
	s.logger.Info("IMAP server stopped")

	return nil
}

// Running returns whether the server is running.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Config returns the server configuration.
func (s *Server) Config() config.IMAPConfig {
	return s.config
}
