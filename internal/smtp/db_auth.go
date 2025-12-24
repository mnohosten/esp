package smtp

import (
	"context"
	"fmt"

	"github.com/mnohosten/esp/internal/database"
	"golang.org/x/crypto/bcrypt"
)

// DBUserAuth implements UserAuthenticator using the database.
type DBUserAuth struct {
	db *database.DB
}

// NewDBUserAuth creates a new database-backed authenticator.
func NewDBUserAuth(db *database.DB) *DBUserAuth {
	return &DBUserAuth{db: db}
}

// Authenticate validates the username (email) and password against the database.
func (a *DBUserAuth) Authenticate(username, password string) error {
	ctx := context.Background()

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
		return fmt.Errorf("user not found: %w", err)
	}

	if !enabled {
		return fmt.Errorf("user disabled")
	}

	// Verify password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return fmt.Errorf("invalid password")
	}

	return nil
}
