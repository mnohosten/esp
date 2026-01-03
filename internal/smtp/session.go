package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/queue"
)

// Session implements smtp.Session and smtp.AuthSession for ESP.
type Session struct {
	conn    *smtp.Conn
	backend *Backend
	logger  *slog.Logger

	// Session state
	from          string
	recipients    []string
	authenticated bool
	username      string
}

// Compile-time check that Session implements AuthSession.
var _ smtp.AuthSession = (*Session)(nil)

// newSession creates a new SMTP session.
func newSession(backend *Backend, conn *smtp.Conn) *Session {
	remoteAddr := conn.Conn().RemoteAddr().String()

	return &Session{
		conn:       conn,
		backend:    backend,
		logger:     backend.Logger().With("remote_addr", remoteAddr),
		recipients: make([]string, 0),
	}
}

// AuthMechanisms returns the list of supported authentication mechanisms.
// This implements smtp.AuthSession.
func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

// Auth handles authentication for the given mechanism.
// This implements smtp.AuthSession.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	if s.backend.authenticator == nil {
		return nil, &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Authentication not available",
		}
	}

	switch mech {
	case sasl.Plain:
		return s.wrapAuthServer(s.backend.authenticator.PlainAuth()), nil
	case sasl.Login:
		return s.wrapAuthServer(s.backend.authenticator.LoginAuth()), nil
	default:
		return nil, &smtp.SMTPError{
			Code:         504,
			EnhancedCode: smtp.EnhancedCode{5, 5, 4},
			Message:      "Unsupported authentication mechanism",
		}
	}
}

// wrapAuthServer wraps a SASL server to track authentication state.
func (s *Session) wrapAuthServer(server sasl.Server) sasl.Server {
	return &authServerWrapper{
		server:  server,
		session: s,
	}
}

// authServerWrapper wraps a SASL server to update session state on success.
type authServerWrapper struct {
	server  sasl.Server
	session *Session
}

// Next implements sasl.Server.
func (w *authServerWrapper) Next(response []byte) (challenge []byte, done bool, err error) {
	challenge, done, err = w.server.Next(response)
	if done && err == nil {
		w.session.authenticated = true
		w.session.logger.Info("authentication successful")
	}
	return
}

// Mail handles the MAIL FROM command.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.logger.Debug("MAIL FROM", "from", from)
	s.from = from
	return nil
}

// Rcpt handles the RCPT TO command.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.logger.Debug("RCPT TO", "to", to)

	// Check recipient limit
	if len(s.recipients) >= s.backend.Config().MaxRecipients {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "Too many recipients",
		}
	}

	s.recipients = append(s.recipients, to)
	return nil
}

// Data handles the DATA command.
func (s *Session) Data(r io.Reader) error {
	s.logger.Debug("DATA", "from", s.from, "recipients", s.recipients, "authenticated", s.authenticated)

	// Read message content
	content, err := io.ReadAll(r)
	if err != nil {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message:      "Failed to read message",
		}
	}

	// Generate message ID
	msgID := uuid.New().String()

	// Check if queue manager is configured
	queueMgr := s.backend.QueueManager()
	queueDir := s.backend.QueueDir()

	// Process each recipient
	ctx := context.Background()
	var outboundRecipients []string
	localDeliverer := s.backend.LocalDeliverer()

	for _, recipient := range s.recipients {
		// Try local delivery first
		if localDeliverer != nil && s.isLocalDelivery(recipient) {
			delivered, err := localDeliverer.DeliverLocal(ctx, s.from, recipient, content)
			if err != nil {
				s.logger.Error("local delivery failed",
					"recipient", recipient,
					"error", err,
				)
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 1, 1},
					Message:      "Recipient rejected",
				}
			}
			if delivered {
				s.logger.Info("message delivered locally",
					"from", s.from,
					"recipient", recipient,
				)
				continue // Successfully delivered locally
			}
			// User not found locally - might need to reject or queue
			s.logger.Debug("recipient not found locally, checking if should queue",
				"recipient", recipient,
			)
		}

		// SECURITY: Only allow outbound relay for authenticated sessions
		if !s.authenticated {
			s.logger.Warn("rejecting relay attempt from unauthenticated session",
				"from", s.from,
				"recipient", recipient,
				"remote_addr", s.conn.Conn().RemoteAddr().String(),
			)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "Relay access denied - authentication required",
			}
		}

		// Queue for outbound delivery (authenticated users only)
		outboundRecipients = append(outboundRecipients, recipient)
	}

	// Queue outbound messages if any
	if len(outboundRecipients) > 0 {
		if queueMgr == nil || queueDir == "" {
			s.logger.Error("no queue configured for outbound delivery",
				"recipients", outboundRecipients,
			)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 0, 0},
				Message:      "Temporary server error",
			}
		}

		// Ensure queue directory exists
		if err := os.MkdirAll(queueDir, 0750); err != nil {
			s.logger.Error("failed to create queue directory", "error", err)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 0, 0},
				Message:      "Temporary server error",
			}
		}

		// Write message to queue file
		msgPath := filepath.Join(queueDir, msgID+".eml")
		if err := os.WriteFile(msgPath, content, 0640); err != nil {
			s.logger.Error("failed to write message to queue", "error", err)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 0, 0},
				Message:      "Failed to store message",
			}
		}

		for _, recipient := range outboundRecipients {
			msg := &queue.Message{
				MessageID:   fmt.Sprintf("<%s@%s>", msgID, s.backend.Config().Hostname),
				Sender:      s.from,
				Recipient:   recipient,
				MessagePath: msgPath,
				Size:        int64(len(content)),
			}

			opts := queue.DefaultEnqueueOptions()
			if err := queueMgr.Enqueue(ctx, msg, opts); err != nil {
				s.logger.Error("failed to enqueue message",
					"recipient", recipient,
					"error", err,
				)
				os.Remove(msgPath)
				return &smtp.SMTPError{
					Code:         451,
					EnhancedCode: smtp.EnhancedCode{4, 0, 0},
					Message:      "Failed to queue message",
				}
			}
		}

		s.logger.Info("message queued for outbound delivery",
			"message_id", msgID,
			"from", s.from,
			"recipients", outboundRecipients,
			"size", len(content),
		)
	}

	return nil
}

// isLocalDelivery checks if the recipient is a local domain.
func (s *Session) isLocalDelivery(recipient string) bool {
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	// For now, consider our hostname as local
	hostname := strings.ToLower(s.backend.Config().Hostname)
	if domain == hostname {
		return true
	}

	// Strip "mail." prefix for comparison
	if strings.HasPrefix(hostname, "mail.") {
		baseDomain := strings.TrimPrefix(hostname, "mail.")
		if domain == baseDomain {
			return true
		}
	}

	return false
}

// Reset resets the session state.
func (s *Session) Reset() {
	s.logger.Debug("RSET")
	s.from = ""
	s.recipients = s.recipients[:0]
}

// Logout handles the QUIT command.
func (s *Session) Logout() error {
	s.logger.Debug("QUIT")
	return nil
}

// Authenticated returns whether the session is authenticated.
func (s *Session) Authenticated() bool {
	return s.authenticated
}

// Username returns the authenticated username.
func (s *Session) Username() string {
	return s.username
}
