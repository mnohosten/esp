package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/database"
	"github.com/mnohosten/esp/internal/storage/maildir"
)

// DBLocalDeliverer implements LocalDeliverer using the database and maildir.
type DBLocalDeliverer struct {
	db      *database.DB
	maildir *maildir.Maildir
	logger  *slog.Logger
}

// NewDBLocalDeliverer creates a new database-backed local deliverer.
func NewDBLocalDeliverer(db *database.DB, md *maildir.Maildir, logger *slog.Logger) *DBLocalDeliverer {
	return &DBLocalDeliverer{
		db:      db,
		maildir: md,
		logger:  logger.With("component", "smtp.local_delivery"),
	}
}

// DeliverLocal delivers a message to a local recipient's mailbox.
func (d *DBLocalDeliverer) DeliverLocal(ctx context.Context, sender, recipient string, content []byte) (bool, error) {
	// Parse recipient email
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid recipient address: %s", recipient)
	}
	localpart := strings.ToLower(parts[0])
	domain := strings.ToLower(parts[1])

	d.logger.Debug("attempting local delivery",
		"sender", sender,
		"recipient", recipient,
		"domain", domain,
		"localpart", localpart,
	)

	// Look up user by email
	var userID uuid.UUID
	var domainEnabled, userEnabled bool

	query := `
		SELECT u.id, d.enabled, u.enabled
		FROM users u
		JOIN domains d ON d.id = u.domain_id
		WHERE LOWER(u.email) = LOWER($1)
	`

	err := d.db.Pool.QueryRow(ctx, query, recipient).Scan(&userID, &domainEnabled, &userEnabled)
	if err != nil {
		d.logger.Debug("user not found for local delivery", "recipient", recipient, "error", err)
		return false, nil // User not found - not a local user
	}

	if !domainEnabled || !userEnabled {
		d.logger.Warn("recipient disabled", "recipient", recipient)
		return false, fmt.Errorf("recipient disabled")
	}

	// Get or create INBOX mailbox
	var mailboxID uuid.UUID
	var uidNext int

	mailboxQuery := `
		SELECT id, uidnext FROM mailboxes
		WHERE user_id = $1 AND name = 'INBOX'
	`
	err = d.db.Pool.QueryRow(ctx, mailboxQuery, userID).Scan(&mailboxID, &uidNext)
	if err != nil {
		// Create INBOX if it doesn't exist
		mailboxID = uuid.New()
		uidNext = 1
		uidValidity := uint32(time.Now().Unix())

		insertQuery := `
			INSERT INTO mailboxes (id, user_id, name, uidvalidity, uidnext, subscribed, message_count, unread_count, created_at, updated_at)
			VALUES ($1, $2, 'INBOX', $3, $4, true, 0, 0, NOW(), NOW())
		`
		_, err = d.db.Pool.Exec(ctx, insertQuery, mailboxID, userID, uidValidity, uidNext)
		if err != nil {
			return false, fmt.Errorf("failed to create INBOX: %w", err)
		}
		d.logger.Info("created INBOX for user", "user_id", userID)
	}

	// Store message in maildir (no flags for new message)
	storeResult, err := d.maildir.StoreMessageBytes(ctx, domain, localpart, "INBOX", content, []string{})
	if err != nil {
		return false, fmt.Errorf("failed to store message in maildir: %w", err)
	}
	msgFilename := storeResult.Filename

	// Insert message record into database
	msgID := uuid.New()
	insertMsgQuery := `
		INSERT INTO messages (id, mailbox_id, uid, message_id, subject, from_address, to_addresses, date, size, flags, storage_path, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, NOW())
	`

	// Extract basic headers (simplified - just for logging)
	subject := extractHeader(content, "Subject")
	messageIDHeader := extractHeader(content, "Message-ID")

	_, err = d.db.Pool.Exec(ctx, insertMsgQuery,
		msgID,
		mailboxID,
		uidNext,
		messageIDHeader,
		subject,
		sender,
		[]string{recipient}, // to_addresses is an array
		len(content),
		[]string{}, // No flags initially
		msgFilename,
	)
	if err != nil {
		return false, fmt.Errorf("failed to insert message record: %w", err)
	}

	// Update mailbox counters
	updateQuery := `
		UPDATE mailboxes
		SET uidnext = uidnext + 1, message_count = message_count + 1, unread_count = unread_count + 1, updated_at = NOW()
		WHERE id = $1
	`
	_, err = d.db.Pool.Exec(ctx, updateQuery, mailboxID)
	if err != nil {
		d.logger.Error("failed to update mailbox counters", "error", err)
	}

	d.logger.Info("message delivered locally",
		"recipient", recipient,
		"mailbox_id", mailboxID,
		"uid", uidNext,
		"size", len(content),
	)

	return true, nil
}

// extractHeader extracts a header value from raw email content.
func extractHeader(content []byte, name string) string {
	lines := strings.Split(string(content), "\n")
	prefix := strings.ToLower(name) + ":"

	for _, line := range lines {
		if line == "" || line == "\r" {
			break // End of headers
		}
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			value := strings.TrimPrefix(line, line[:len(prefix)])
			return strings.TrimSpace(value)
		}
	}
	return ""
}
