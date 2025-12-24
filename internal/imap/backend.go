package imap

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/database"
	"github.com/mnohosten/esp/internal/mailbox"
	"github.com/mnohosten/esp/internal/storage/maildir"
	"golang.org/x/crypto/bcrypt"
)

// Backend implements the IMAP backend for ESP.
type Backend struct {
	db           *database.DB
	mailboxMgr   *mailbox.Manager
	messageStore *mailbox.MessageStore
	searcher     *mailbox.Searcher
	quotaMgr     *mailbox.QuotaManager
	maildir      *maildir.Maildir
	logger       *slog.Logger
}

// NewBackend creates a new IMAP backend.
func NewBackend(
	db *database.DB,
	mailboxMgr *mailbox.Manager,
	messageStore *mailbox.MessageStore,
	searcher *mailbox.Searcher,
	quotaMgr *mailbox.QuotaManager,
	maildir *maildir.Maildir,
	logger *slog.Logger,
) *Backend {
	return &Backend{
		db:           db,
		mailboxMgr:   mailboxMgr,
		messageStore: messageStore,
		searcher:     searcher,
		quotaMgr:     quotaMgr,
		maildir:      maildir,
		logger:       logger.With("component", "imap-backend"),
	}
}

// NewSession creates a new session for a connection.
func (b *Backend) NewSession(conn net.Conn) *Session {
	return &Session{
		backend:    b,
		conn:       conn,
		remoteAddr: conn.RemoteAddr().String(),
		logger:     b.logger.With("remote_addr", conn.RemoteAddr().String()),
	}
}

// Authenticate authenticates a user with username and password.
func (b *Backend) Authenticate(ctx context.Context, username, password string) (*User, error) {
	// Look up user by email
	query := `
		SELECT u.id, u.domain_id, u.username, u.email, u.password_hash, u.display_name,
		       u.enabled, u.is_admin, u.quota_bytes, u.used_bytes, d.name as domain
		FROM users u
		JOIN domains d ON d.id = u.domain_id
		WHERE u.email = $1 AND u.enabled = true AND d.enabled = true
	`

	var user User
	var passwordHash string
	err := b.db.Pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.DomainID, &user.Username, &user.Email, &passwordHash,
		&user.DisplayName, &user.Enabled, &user.IsAdmin, &user.QuotaBytes,
		&user.UsedBytes, &user.Domain,
	)
	if err != nil {
		b.logger.Debug("user not found", "username", username)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		b.logger.Debug("password mismatch", "username", username)
		return nil, fmt.Errorf("invalid credentials")
	}

	b.logger.Info("user authenticated",
		"user_id", user.ID,
		"email", user.Email,
	)

	// Update last login
	go func() {
		updateQuery := `UPDATE users SET last_login = NOW() WHERE id = $1`
		b.db.Pool.Exec(context.Background(), updateQuery, user.ID)
	}()

	return &user, nil
}

// User represents an authenticated user.
type User struct {
	ID          uuid.UUID
	DomainID    uuid.UUID
	Username    string
	Email       string
	DisplayName *string
	Enabled     bool
	IsAdmin     bool
	QuotaBytes  int64
	UsedBytes   int64
	Domain      string
}

// Localpart returns the local part of the email address.
func (u *User) Localpart() string {
	return u.Username
}
