package mailbox

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mnohosten/esp/internal/database"
	"github.com/mnohosten/esp/internal/storage/maildir"
)

// Special-use mailbox attributes (RFC 6154)
const (
	SpecialUseInbox   = "\\Inbox"
	SpecialUseSent    = "\\Sent"
	SpecialUseDrafts  = "\\Drafts"
	SpecialUseTrash   = "\\Trash"
	SpecialUseJunk    = "\\Junk"
	SpecialUseArchive = "\\Archive"
)

// Default mailboxes created for new users
var DefaultMailboxes = []struct {
	Name       string
	SpecialUse string
}{
	{"INBOX", SpecialUseInbox},
	{"Sent", SpecialUseSent},
	{"Drafts", SpecialUseDrafts},
	{"Trash", SpecialUseTrash},
	{"Junk", SpecialUseJunk},
}

// Mailbox represents an IMAP mailbox (folder)
type Mailbox struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	Name         string     `json:"name"`
	UIDValidity  uint32     `json:"uid_validity"`
	UIDNext      uint32     `json:"uid_next"`
	Subscribed   bool       `json:"subscribed"`
	SpecialUse   string     `json:"special_use,omitempty"`
	MessageCount int        `json:"message_count"`
	UnreadCount  int        `json:"unread_count"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Manager handles mailbox operations
type Manager struct {
	db      *database.DB
	maildir *maildir.Maildir
	logger  *slog.Logger
}

// NewManager creates a new mailbox manager
func NewManager(db *database.DB, maildir *maildir.Maildir, logger *slog.Logger) *Manager {
	return &Manager{
		db:      db,
		maildir: maildir,
		logger:  logger.With("component", "mailbox-manager"),
	}
}

// generateUIDValidity generates a unique UID validity value
// Using timestamp ensures it changes if mailbox is recreated
func generateUIDValidity() uint32 {
	return uint32(time.Now().Unix()) + uint32(rand.Intn(1000))
}

// Create creates a new mailbox for a user
func (m *Manager) Create(ctx context.Context, userID uuid.UUID, name string, specialUse string) (*Mailbox, error) {
	// Get user info for maildir path
	user, err := m.getUserInfo(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Create maildir structure on disk (skip for INBOX, it's created with user)
	if name != "INBOX" {
		if err := m.maildir.CreateMailbox(ctx, user.Domain, user.Localpart, name); err != nil {
			return nil, fmt.Errorf("failed to create maildir: %w", err)
		}
	}

	// Generate UID validity
	uidValidity := generateUIDValidity()

	// Insert into database
	mailbox := &Mailbox{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        name,
		UIDValidity: uidValidity,
		UIDNext:     1,
		Subscribed:  true, // Subscribe by default
		SpecialUse:  specialUse,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `
		INSERT INTO mailboxes (id, user_id, name, uidvalidity, uidnext, subscribed, special_use, message_count, unread_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = m.db.Pool.Exec(ctx, query,
		mailbox.ID, mailbox.UserID, mailbox.Name, mailbox.UIDValidity, mailbox.UIDNext,
		mailbox.Subscribed, nullString(mailbox.SpecialUse), mailbox.MessageCount, mailbox.UnreadCount,
		mailbox.CreatedAt, mailbox.UpdatedAt,
	)
	if err != nil {
		// Clean up maildir on DB error
		if name != "INBOX" {
			m.maildir.DeleteMailbox(ctx, user.Domain, user.Localpart, name)
		}
		return nil, fmt.Errorf("failed to insert mailbox: %w", err)
	}

	m.logger.Info("mailbox created",
		"mailbox_id", mailbox.ID,
		"user_id", userID,
		"name", name,
		"special_use", specialUse,
	)

	return mailbox, nil
}

// Get retrieves a mailbox by ID
func (m *Manager) Get(ctx context.Context, mailboxID uuid.UUID) (*Mailbox, error) {
	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE id = $1
	`

	var mb Mailbox
	var specialUse *string
	err := m.db.Pool.QueryRow(ctx, query, mailboxID).Scan(
		&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
		&mb.Subscribed, &specialUse, &mb.MessageCount, &mb.UnreadCount,
		&mb.CreatedAt, &mb.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("mailbox not found: %s", mailboxID)
		}
		return nil, fmt.Errorf("failed to get mailbox: %w", err)
	}

	if specialUse != nil {
		mb.SpecialUse = *specialUse
	}

	return &mb, nil
}

// GetByName retrieves a mailbox by user ID and name
func (m *Manager) GetByName(ctx context.Context, userID uuid.UUID, name string) (*Mailbox, error) {
	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE user_id = $1 AND name = $2
	`

	var mb Mailbox
	var specialUse *string
	err := m.db.Pool.QueryRow(ctx, query, userID, name).Scan(
		&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
		&mb.Subscribed, &specialUse, &mb.MessageCount, &mb.UnreadCount,
		&mb.CreatedAt, &mb.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("mailbox not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get mailbox: %w", err)
	}

	if specialUse != nil {
		mb.SpecialUse = *specialUse
	}

	return &mb, nil
}

// GetBySpecialUse retrieves a mailbox by user ID and special-use attribute
func (m *Manager) GetBySpecialUse(ctx context.Context, userID uuid.UUID, specialUse string) (*Mailbox, error) {
	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE user_id = $1 AND special_use = $2
	`

	var mb Mailbox
	var specialUsePtr *string
	err := m.db.Pool.QueryRow(ctx, query, userID, specialUse).Scan(
		&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
		&mb.Subscribed, &specialUsePtr, &mb.MessageCount, &mb.UnreadCount,
		&mb.CreatedAt, &mb.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("mailbox with special use %s not found", specialUse)
		}
		return nil, fmt.Errorf("failed to get mailbox: %w", err)
	}

	if specialUsePtr != nil {
		mb.SpecialUse = *specialUsePtr
	}

	return &mb, nil
}

// List returns all mailboxes for a user
func (m *Manager) List(ctx context.Context, userID uuid.UUID) ([]*Mailbox, error) {
	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE user_id = $1
		ORDER BY
			CASE WHEN special_use = '\Inbox' THEN 0
			     WHEN special_use = '\Sent' THEN 1
			     WHEN special_use = '\Drafts' THEN 2
			     WHEN special_use = '\Trash' THEN 3
			     WHEN special_use = '\Junk' THEN 4
			     WHEN special_use = '\Archive' THEN 5
			     ELSE 6
			END,
			name
	`

	rows, err := m.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*Mailbox
	for rows.Next() {
		var mb Mailbox
		var specialUse *string
		err := rows.Scan(
			&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
			&mb.Subscribed, &specialUse, &mb.MessageCount, &mb.UnreadCount,
			&mb.CreatedAt, &mb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}
		if specialUse != nil {
			mb.SpecialUse = *specialUse
		}
		mailboxes = append(mailboxes, &mb)
	}

	return mailboxes, nil
}

// ListSubscribed returns only subscribed mailboxes for a user
func (m *Manager) ListSubscribed(ctx context.Context, userID uuid.UUID) ([]*Mailbox, error) {
	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE user_id = $1 AND subscribed = true
		ORDER BY
			CASE WHEN special_use = '\Inbox' THEN 0
			     WHEN special_use = '\Sent' THEN 1
			     WHEN special_use = '\Drafts' THEN 2
			     WHEN special_use = '\Trash' THEN 3
			     WHEN special_use = '\Junk' THEN 4
			     WHEN special_use = '\Archive' THEN 5
			     ELSE 6
			END,
			name
	`

	rows, err := m.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*Mailbox
	for rows.Next() {
		var mb Mailbox
		var specialUse *string
		err := rows.Scan(
			&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
			&mb.Subscribed, &specialUse, &mb.MessageCount, &mb.UnreadCount,
			&mb.CreatedAt, &mb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}
		if specialUse != nil {
			mb.SpecialUse = *specialUse
		}
		mailboxes = append(mailboxes, &mb)
	}

	return mailboxes, nil
}

// ListByPattern returns mailboxes matching an IMAP LIST pattern
// Pattern supports '*' (any substring) and '%' (any except hierarchy delimiter)
func (m *Manager) ListByPattern(ctx context.Context, userID uuid.UUID, pattern string) ([]*Mailbox, error) {
	// Convert IMAP pattern to SQL LIKE pattern
	// '*' matches any string including '/'
	// '%' matches any string except '/'
	sqlPattern := pattern
	sqlPattern = replaceAll(sqlPattern, "*", "%")
	// For '%' (non-hierarchical), we'd need more complex logic
	// For now, treat '%' same as '*'

	query := `
		SELECT id, user_id, name, uidvalidity, uidnext, subscribed, special_use,
		       message_count, unread_count, created_at, updated_at
		FROM mailboxes
		WHERE user_id = $1 AND name LIKE $2
		ORDER BY name
	`

	rows, err := m.db.Pool.Query(ctx, query, userID, sqlPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*Mailbox
	for rows.Next() {
		var mb Mailbox
		var specialUse *string
		err := rows.Scan(
			&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
			&mb.Subscribed, &specialUse, &mb.MessageCount, &mb.UnreadCount,
			&mb.CreatedAt, &mb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}
		if specialUse != nil {
			mb.SpecialUse = *specialUse
		}
		mailboxes = append(mailboxes, &mb)
	}

	return mailboxes, nil
}

// Delete deletes a mailbox and all its messages
func (m *Manager) Delete(ctx context.Context, mailboxID uuid.UUID) error {
	// Get mailbox info
	mb, err := m.Get(ctx, mailboxID)
	if err != nil {
		return err
	}

	// Cannot delete INBOX
	if mb.SpecialUse == SpecialUseInbox || mb.Name == "INBOX" {
		return fmt.Errorf("cannot delete INBOX")
	}

	// Get user info for maildir path
	user, err := m.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Delete from database first (this cascades to messages)
	query := `DELETE FROM mailboxes WHERE id = $1`
	result, err := m.db.Pool.Exec(ctx, query, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to delete mailbox: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("mailbox not found")
	}

	// Delete maildir structure
	if err := m.maildir.DeleteMailbox(ctx, user.Domain, user.Localpart, mb.Name); err != nil {
		m.logger.Error("failed to delete maildir",
			"mailbox_id", mailboxID,
			"name", mb.Name,
			"error", err,
		)
		// Don't fail - DB is already updated
	}

	m.logger.Info("mailbox deleted",
		"mailbox_id", mailboxID,
		"user_id", mb.UserID,
		"name", mb.Name,
	)

	return nil
}

// Rename renames a mailbox
func (m *Manager) Rename(ctx context.Context, mailboxID uuid.UUID, newName string) error {
	// Get mailbox info
	mb, err := m.Get(ctx, mailboxID)
	if err != nil {
		return err
	}

	// Cannot rename INBOX
	if mb.SpecialUse == SpecialUseInbox || mb.Name == "INBOX" {
		return fmt.Errorf("cannot rename INBOX")
	}

	// Get user info for maildir path
	user, err := m.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Rename maildir first
	if err := m.maildir.RenameMailbox(ctx, user.Domain, user.Localpart, mb.Name, newName); err != nil {
		return fmt.Errorf("failed to rename maildir: %w", err)
	}

	// Update database
	query := `UPDATE mailboxes SET name = $1 WHERE id = $2`
	_, err = m.db.Pool.Exec(ctx, query, newName, mailboxID)
	if err != nil {
		// Try to rollback maildir rename
		m.maildir.RenameMailbox(ctx, user.Domain, user.Localpart, newName, mb.Name)
		return fmt.Errorf("failed to update mailbox name: %w", err)
	}

	m.logger.Info("mailbox renamed",
		"mailbox_id", mailboxID,
		"old_name", mb.Name,
		"new_name", newName,
	)

	return nil
}

// Subscribe subscribes a user to a mailbox
func (m *Manager) Subscribe(ctx context.Context, mailboxID uuid.UUID) error {
	query := `UPDATE mailboxes SET subscribed = true WHERE id = $1`
	result, err := m.db.Pool.Exec(ctx, query, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("mailbox not found")
	}
	return nil
}

// Unsubscribe unsubscribes a user from a mailbox
func (m *Manager) Unsubscribe(ctx context.Context, mailboxID uuid.UUID) error {
	query := `UPDATE mailboxes SET subscribed = false WHERE id = $1`
	result, err := m.db.Pool.Exec(ctx, query, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to unsubscribe: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("mailbox not found")
	}
	return nil
}

// IncrementUIDNext increments the UID next value and returns the new UID
func (m *Manager) IncrementUIDNext(ctx context.Context, mailboxID uuid.UUID) (uint32, error) {
	query := `
		UPDATE mailboxes
		SET uidnext = uidnext + 1
		WHERE id = $1
		RETURNING uidnext - 1
	`

	var uid uint32
	err := m.db.Pool.QueryRow(ctx, query, mailboxID).Scan(&uid)
	if err != nil {
		return 0, fmt.Errorf("failed to increment UID next: %w", err)
	}

	return uid, nil
}

// UpdateCounts updates the message and unread counts for a mailbox
func (m *Manager) UpdateCounts(ctx context.Context, mailboxID uuid.UUID) error {
	query := `
		UPDATE mailboxes SET
			message_count = (SELECT COUNT(*) FROM messages WHERE mailbox_id = $1),
			unread_count = (SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND NOT ('\Seen' = ANY(flags)))
		WHERE id = $1
	`

	_, err := m.db.Pool.Exec(ctx, query, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to update counts: %w", err)
	}

	return nil
}

// IncrementMessageCount increments the message count
func (m *Manager) IncrementMessageCount(ctx context.Context, mailboxID uuid.UUID, delta int) error {
	query := `UPDATE mailboxes SET message_count = message_count + $1 WHERE id = $2`
	_, err := m.db.Pool.Exec(ctx, query, delta, mailboxID)
	return err
}

// IncrementUnreadCount increments the unread count
func (m *Manager) IncrementUnreadCount(ctx context.Context, mailboxID uuid.UUID, delta int) error {
	query := `UPDATE mailboxes SET unread_count = unread_count + $1 WHERE id = $2`
	_, err := m.db.Pool.Exec(ctx, query, delta, mailboxID)
	return err
}

// CreateDefaultMailboxes creates the default mailboxes for a new user
func (m *Manager) CreateDefaultMailboxes(ctx context.Context, userID uuid.UUID) error {
	// Get user info for maildir creation
	user, err := m.getUserInfo(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Create maildir structure on disk
	if err := m.maildir.CreateUserMaildir(ctx, user.Domain, user.Localpart); err != nil {
		return fmt.Errorf("failed to create user maildir: %w", err)
	}

	// Create default mailboxes in database
	for _, mb := range DefaultMailboxes {
		_, err := m.Create(ctx, userID, mb.Name, mb.SpecialUse)
		if err != nil {
			m.logger.Error("failed to create default mailbox",
				"user_id", userID,
				"mailbox", mb.Name,
				"error", err,
			)
			// Continue with other mailboxes
		}
	}

	return nil
}

// Exists checks if a mailbox exists
func (m *Manager) Exists(ctx context.Context, userID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM mailboxes WHERE user_id = $1 AND name = $2)`
	var exists bool
	err := m.db.Pool.QueryRow(ctx, query, userID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check mailbox existence: %w", err)
	}
	return exists, nil
}

// userInfo holds basic user information needed for maildir operations
type userInfo struct {
	Domain    string
	Localpart string
}

// getUserInfo retrieves user domain and localpart for maildir path construction
func (m *Manager) getUserInfo(ctx context.Context, userID uuid.UUID) (*userInfo, error) {
	query := `
		SELECT d.name, u.username
		FROM users u
		JOIN domains d ON d.id = u.domain_id
		WHERE u.id = $1
	`

	var info userInfo
	err := m.db.Pool.QueryRow(ctx, query, userID).Scan(&info.Domain, &info.Localpart)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", userID)
		}
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &info, nil
}

// nullString returns nil for empty strings, otherwise the string pointer
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// replaceAll is a simple string replacement helper
func replaceAll(s, old, new string) string {
	result := s
	for {
		newResult := ""
		found := false
		for i := 0; i < len(result); i++ {
			if i+len(old) <= len(result) && result[i:i+len(old)] == old {
				newResult += new
				i += len(old) - 1
				found = true
			} else {
				newResult += string(result[i])
			}
		}
		if !found {
			break
		}
		result = newResult
	}
	return result
}
