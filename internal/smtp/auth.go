package smtp

import (
	"errors"
	"log/slog"

	"github.com/emersion/go-sasl"
)

var (
	// ErrAuthFailed is returned when authentication fails.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrAuthRequired is returned when authentication is required but not provided.
	ErrAuthRequired = errors.New("authentication required")
)

// UserAuthenticator is the interface for authenticating users.
// This will be implemented by the user store.
type UserAuthenticator interface {
	// Authenticate validates the username and password.
	// Returns nil if authentication succeeds, error otherwise.
	Authenticate(username, password string) error
}

// Authenticator handles SMTP authentication mechanisms.
type Authenticator struct {
	userAuth UserAuthenticator
	logger   *slog.Logger
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(userAuth UserAuthenticator, logger *slog.Logger) *Authenticator {
	return &Authenticator{
		userAuth: userAuth,
		logger:   logger.With("component", "smtp.auth"),
	}
}

// PlainAuth returns a SASL server for PLAIN authentication.
// PLAIN authentication sends identity, username, and password in a single message.
func (a *Authenticator) PlainAuth() sasl.Server {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		a.logger.Debug("PLAIN auth attempt", "username", username, "identity", identity)

		if err := a.userAuth.Authenticate(username, password); err != nil {
			a.logger.Warn("PLAIN auth failed", "username", username, "error", err)
			return ErrAuthFailed
		}

		a.logger.Info("PLAIN auth succeeded", "username", username)
		return nil
	})
}

// LoginAuth returns a SASL server for LOGIN authentication.
// LOGIN authentication is a legacy mechanism that prompts for username and password separately.
func (a *Authenticator) LoginAuth() sasl.Server {
	return &loginServer{
		userAuth: a.userAuth,
		logger:   a.logger,
	}
}

// loginServer implements sasl.Server for the LOGIN mechanism.
type loginServer struct {
	userAuth UserAuthenticator
	logger   *slog.Logger
	username string
	step     int
}

// Next processes the next step of LOGIN authentication.
func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		// Initial state - send username prompt
		s.step++
		return []byte("Username:"), false, nil
	case 1:
		// Received username - send password prompt
		s.username = string(response)
		s.step++
		return []byte("Password:"), false, nil
	case 2:
		// Received password - authenticate
		password := string(response)
		s.logger.Debug("LOGIN auth attempt", "username", s.username)

		if err := s.userAuth.Authenticate(s.username, password); err != nil {
			s.logger.Warn("LOGIN auth failed", "username", s.username, "error", err)
			return nil, false, ErrAuthFailed
		}

		s.logger.Info("LOGIN auth succeeded", "username", s.username)
		return nil, true, nil
	default:
		return nil, false, errors.New("unexpected LOGIN state")
	}
}

// staticUserAuth is a simple implementation for testing.
// In production, this would be replaced by a real user store.
type staticUserAuth struct {
	users map[string]string // username -> password
}

// NewStaticUserAuth creates a UserAuthenticator with static credentials.
// This is useful for testing and development.
func NewStaticUserAuth(users map[string]string) UserAuthenticator {
	return &staticUserAuth{users: users}
}

// Authenticate checks credentials against the static user map.
func (s *staticUserAuth) Authenticate(username, password string) error {
	if expectedPassword, ok := s.users[username]; ok {
		if expectedPassword == password {
			return nil
		}
	}
	return ErrAuthFailed
}
