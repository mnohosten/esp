package smtp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mnohosten/esp/internal/database"
	"golang.org/x/crypto/bcrypt"
)

// DBUserAuth implements UserAuthenticator using the database.
type DBUserAuth struct {
	db     *database.DB
	logger *slog.Logger
}

// NewDBUserAuth creates a new database-backed authenticator.
func NewDBUserAuth(db *database.DB, logger *slog.Logger) *DBUserAuth {
	return &DBUserAuth{
		db:     db,
		logger: logger.With("component", "smtp.db_auth"),
	}
}

// Authenticate validates the username (email) and password against the database.
func (a *DBUserAuth) Authenticate(username, password string) error {
	ctx := context.Background()

	a.logger.Debug("authenticating user", "username", username, "password_len", len(password))

	var passwordHash string
	var enabled bool

	query := `
		SELECT u.password_hash, u.enabled
		FROM users u
		JOIN domains d ON d.id = u.domain_id
		WHERE u.email = $1 AND d.enabled = true
	`

	err := a.db.Pool.QueryRow(ctx, query, username).Scan(&passwordHash, &enabled)
	if err != nil {
		a.logger.Debug("user lookup failed", "username", username, "error", err)
		return fmt.Errorf("user not found: %w", err)
	}

	a.logger.Debug("user found", "username", username, "enabled", enabled, "hash_prefix", passwordHash[:10])

	if !enabled {
		return fmt.Errorf("user disabled")
	}

	// Verify password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		a.logger.Debug("password mismatch", "username", username, "bcrypt_error", err)
		return fmt.Errorf("invalid password")
	}

	a.logger.Debug("authentication successful", "username", username)
	return nil
}
