package smtp

import (
	"io"
	"log/slog"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
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

	// TODO: Implement message processing:
	// 1. Parse message with go-message
	// 2. Run through filter chain
	// 3. Verify SPF/DKIM/DMARC
	// 4. Store locally or queue for delivery

	// For now, just consume the data
	_, err := io.Copy(io.Discard, r)
	if err != nil {
		return err
	}

	s.logger.Info("message received",
		"from", s.from,
		"recipients", s.recipients,
		"authenticated", s.authenticated,
	)

	return nil
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
