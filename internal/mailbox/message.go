package mailbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mnohosten/esp/internal/database"
	"github.com/mnohosten/esp/internal/storage/maildir"
)

// Message represents a stored email message with metadata
type Message struct {
	ID           uuid.UUID         `json:"id"`
	MailboxID    uuid.UUID         `json:"mailbox_id"`
	UID          uint32            `json:"uid"`
	MessageID    string            `json:"message_id,omitempty"`
	InReplyTo    string            `json:"in_reply_to,omitempty"`
	Subject      string            `json:"subject,omitempty"`
	FromAddress  string            `json:"from_address,omitempty"`
	ToAddresses  []string          `json:"to_addresses,omitempty"`
	CcAddresses  []string          `json:"cc_addresses,omitempty"`
	Date         *time.Time        `json:"date,omitempty"`
	Size         int64             `json:"size"`
	StoragePath  string            `json:"storage_path"`
	Flags        []string          `json:"flags"`
	InternalDate time.Time         `json:"internal_date"`
	HeadersJSON  map[string]string `json:"headers_json,omitempty"`
	BodyText     string            `json:"body_text,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// MessageStore handles message storage and retrieval
type MessageStore struct {
	db      *database.DB
	maildir *maildir.Maildir
	mbMgr   *Manager
	logger  *slog.Logger
}

// NewMessageStore creates a new message store
func NewMessageStore(db *database.DB, maildir *maildir.Maildir, mbMgr *Manager, logger *slog.Logger) *MessageStore {
	return &MessageStore{
		db:      db,
		maildir: maildir,
		mbMgr:   mbMgr,
		logger:  logger.With("component", "message-store"),
	}
}

// StoreMessage stores a new message in both maildir and database
func (s *MessageStore) StoreMessage(ctx context.Context, mailboxID uuid.UUID, content []byte, flags []string) (*Message, error) {
	// Get mailbox to find user info
	mb, err := s.mbMgr.Get(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mailbox: %w", err)
	}

	// Get user info for maildir path
	user, err := s.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Store in maildir
	result, err := s.maildir.StoreMessageBytes(ctx, user.Domain, user.Localpart, mb.Name, content, flags)
	if err != nil {
		return nil, fmt.Errorf("failed to store in maildir: %w", err)
	}

	// Parse email to extract metadata
	parsed, err := s.parseEmail(content)
	if err != nil {
		s.logger.Warn("failed to parse email, storing with minimal metadata",
			"error", err,
		)
		parsed = &parsedEmail{}
	}

	// Get next UID
	uid, err := s.mbMgr.IncrementUIDNext(ctx, mailboxID)
	if err != nil {
		// Clean up maildir
		s.maildir.DeleteMessage(ctx, user.Domain, user.Localpart, mb.Name, result.Filename)
		return nil, fmt.Errorf("failed to get UID: %w", err)
	}

	// Prepare headers JSON
	var headersJSON []byte
	if parsed.Headers != nil {
		headersJSON, _ = json.Marshal(parsed.Headers)
	}

	// Create message record
	msg := &Message{
		ID:           uuid.New(),
		MailboxID:    mailboxID,
		UID:          uid,
		MessageID:    parsed.MessageID,
		InReplyTo:    parsed.InReplyTo,
		Subject:      parsed.Subject,
		FromAddress:  parsed.From,
		ToAddresses:  parsed.To,
		CcAddresses:  parsed.Cc,
		Date:         parsed.Date,
		Size:         result.Size,
		StoragePath:  result.Filename,
		Flags:        flags,
		InternalDate: time.Now(),
		HeadersJSON:  parsed.Headers,
		BodyText:     parsed.BodyText,
		CreatedAt:    time.Now(),
	}

	// Insert into database
	query := `
		INSERT INTO messages (
			id, mailbox_id, uid, message_id, in_reply_to, subject,
			from_address, to_addresses, cc_addresses, date, size,
			storage_path, flags, internal_date, headers_json, body_text, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)
	`

	_, err = s.db.Pool.Exec(ctx, query,
		msg.ID, msg.MailboxID, msg.UID, nullString(msg.MessageID), nullString(msg.InReplyTo),
		nullString(msg.Subject), nullString(msg.FromAddress), msg.ToAddresses, msg.CcAddresses,
		msg.Date, msg.Size, msg.StoragePath, msg.Flags, msg.InternalDate,
		headersJSON, nullString(msg.BodyText), msg.CreatedAt,
	)
	if err != nil {
		// Clean up maildir
		s.maildir.DeleteMessage(ctx, user.Domain, user.Localpart, mb.Name, result.Filename)
		return nil, fmt.Errorf("failed to insert message: %w", err)
	}

	// Update mailbox counts
	if err := s.mbMgr.IncrementMessageCount(ctx, mailboxID, 1); err != nil {
		s.logger.Warn("failed to update message count", "error", err)
	}
	if !containsFlag(flags, "\\Seen") {
		if err := s.mbMgr.IncrementUnreadCount(ctx, mailboxID, 1); err != nil {
			s.logger.Warn("failed to update unread count", "error", err)
		}
	}

	s.logger.Info("message stored",
		"message_id", msg.ID,
		"mailbox_id", mailboxID,
		"uid", uid,
		"size", result.Size,
	)

	return msg, nil
}

// GetMessage retrieves a message by mailbox ID and UID
func (s *MessageStore) GetMessage(ctx context.Context, mailboxID uuid.UUID, uid uint32) (*Message, error) {
	query := `
		SELECT id, mailbox_id, uid, message_id, in_reply_to, subject,
		       from_address, to_addresses, cc_addresses, date, size,
		       storage_path, flags, internal_date, headers_json, body_text, created_at
		FROM messages
		WHERE mailbox_id = $1 AND uid = $2
	`

	return s.scanMessage(s.db.Pool.QueryRow(ctx, query, mailboxID, uid))
}

// GetMessageByID retrieves a message by its UUID
func (s *MessageStore) GetMessageByID(ctx context.Context, messageID uuid.UUID) (*Message, error) {
	query := `
		SELECT id, mailbox_id, uid, message_id, in_reply_to, subject,
		       from_address, to_addresses, cc_addresses, date, size,
		       storage_path, flags, internal_date, headers_json, body_text, created_at
		FROM messages
		WHERE id = $1
	`

	return s.scanMessage(s.db.Pool.QueryRow(ctx, query, messageID))
}

// GetMessagesByRange retrieves messages within a UID range
func (s *MessageStore) GetMessagesByRange(ctx context.Context, mailboxID uuid.UUID, startUID, endUID uint32) ([]*Message, error) {
	query := `
		SELECT id, mailbox_id, uid, message_id, in_reply_to, subject,
		       from_address, to_addresses, cc_addresses, date, size,
		       storage_path, flags, internal_date, headers_json, body_text, created_at
		FROM messages
		WHERE mailbox_id = $1 AND uid >= $2 AND uid <= $3
		ORDER BY uid
	`

	rows, err := s.db.Pool.Query(ctx, query, mailboxID, startUID, endUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	return s.scanMessages(rows)
}

// GetAllMessages retrieves all messages in a mailbox
func (s *MessageStore) GetAllMessages(ctx context.Context, mailboxID uuid.UUID) ([]*Message, error) {
	query := `
		SELECT id, mailbox_id, uid, message_id, in_reply_to, subject,
		       from_address, to_addresses, cc_addresses, date, size,
		       storage_path, flags, internal_date, headers_json, body_text, created_at
		FROM messages
		WHERE mailbox_id = $1
		ORDER BY uid
	`

	rows, err := s.db.Pool.Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	return s.scanMessages(rows)
}

// GetMessageContent retrieves the raw message content from maildir
func (s *MessageStore) GetMessageContent(ctx context.Context, mailboxID uuid.UUID, uid uint32) ([]byte, error) {
	msg, err := s.GetMessage(ctx, mailboxID, uid)
	if err != nil {
		return nil, err
	}

	mb, err := s.mbMgr.Get(ctx, mailboxID)
	if err != nil {
		return nil, err
	}

	user, err := s.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return nil, err
	}

	return s.maildir.GetMessage(ctx, user.Domain, user.Localpart, mb.Name, msg.StoragePath)
}

// DeleteMessage deletes a message from both maildir and database
func (s *MessageStore) DeleteMessage(ctx context.Context, mailboxID uuid.UUID, uid uint32) error {
	// Get message for storage path
	msg, err := s.GetMessage(ctx, mailboxID, uid)
	if err != nil {
		return err
	}

	mb, err := s.mbMgr.Get(ctx, mailboxID)
	if err != nil {
		return err
	}

	user, err := s.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return err
	}

	// Delete from database first
	query := `DELETE FROM messages WHERE mailbox_id = $1 AND uid = $2`
	result, err := s.db.Pool.Exec(ctx, query, mailboxID, uid)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("message not found")
	}

	// Delete from maildir
	if err := s.maildir.DeleteMessage(ctx, user.Domain, user.Localpart, mb.Name, msg.StoragePath); err != nil {
		s.logger.Warn("failed to delete from maildir", "error", err)
	}

	// Update counts
	if err := s.mbMgr.IncrementMessageCount(ctx, mailboxID, -1); err != nil {
		s.logger.Warn("failed to update message count", "error", err)
	}
	if !containsFlag(msg.Flags, "\\Seen") {
		if err := s.mbMgr.IncrementUnreadCount(ctx, mailboxID, -1); err != nil {
			s.logger.Warn("failed to update unread count", "error", err)
		}
	}

	return nil
}

// DeleteMessages deletes multiple messages by UID
func (s *MessageStore) DeleteMessages(ctx context.Context, mailboxID uuid.UUID, uids []uint32) error {
	for _, uid := range uids {
		if err := s.DeleteMessage(ctx, mailboxID, uid); err != nil {
			return err
		}
	}
	return nil
}

// SetFlags sets the flags for a message (replaces existing flags)
func (s *MessageStore) SetFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error {
	// Get current message
	msg, err := s.GetMessage(ctx, mailboxID, uid)
	if err != nil {
		return err
	}

	wasSeen := containsFlag(msg.Flags, "\\Seen")
	isSeen := containsFlag(flags, "\\Seen")

	// Update database
	query := `UPDATE messages SET flags = $1 WHERE mailbox_id = $2 AND uid = $3`
	_, err = s.db.Pool.Exec(ctx, query, flags, mailboxID, uid)
	if err != nil {
		return fmt.Errorf("failed to update flags: %w", err)
	}

	// Update maildir filename
	mb, err := s.mbMgr.Get(ctx, mailboxID)
	if err != nil {
		return err
	}
	user, err := s.getUserInfo(ctx, mb.UserID)
	if err != nil {
		return err
	}

	newFilename, err := s.maildir.UpdateMessageFlags(ctx, user.Domain, user.Localpart, mb.Name, msg.StoragePath, flags)
	if err != nil {
		s.logger.Warn("failed to update maildir flags", "error", err)
	} else if newFilename != msg.StoragePath {
		// Update storage path in database
		query := `UPDATE messages SET storage_path = $1 WHERE mailbox_id = $2 AND uid = $3`
		s.db.Pool.Exec(ctx, query, newFilename, mailboxID, uid)
	}

	// Update unread count if Seen flag changed
	if wasSeen != isSeen {
		delta := 1
		if isSeen {
			delta = -1
		}
		s.mbMgr.IncrementUnreadCount(ctx, mailboxID, delta)
	}

	return nil
}

// AddFlags adds flags to a message
func (s *MessageStore) AddFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error {
	msg, err := s.GetMessage(ctx, mailboxID, uid)
	if err != nil {
		return err
	}

	// Merge flags
	newFlags := mergeFlags(msg.Flags, flags)
	return s.SetFlags(ctx, mailboxID, uid, newFlags)
}

// RemoveFlags removes flags from a message
func (s *MessageStore) RemoveFlags(ctx context.Context, mailboxID uuid.UUID, uid uint32, flags []string) error {
	msg, err := s.GetMessage(ctx, mailboxID, uid)
	if err != nil {
		return err
	}

	// Remove flags
	newFlags := removeFlags(msg.Flags, flags)
	return s.SetFlags(ctx, mailboxID, uid, newFlags)
}

// MoveMessage moves a message to another mailbox
func (s *MessageStore) MoveMessage(ctx context.Context, srcMailboxID, dstMailboxID uuid.UUID, uid uint32) (uint32, error) {
	// Get message content
	content, err := s.GetMessageContent(ctx, srcMailboxID, uid)
	if err != nil {
		return 0, err
	}

	// Get original message for flags
	origMsg, err := s.GetMessage(ctx, srcMailboxID, uid)
	if err != nil {
		return 0, err
	}

	// Store in destination
	newMsg, err := s.StoreMessage(ctx, dstMailboxID, content, origMsg.Flags)
	if err != nil {
		return 0, err
	}

	// Delete from source
	if err := s.DeleteMessage(ctx, srcMailboxID, uid); err != nil {
		s.logger.Warn("failed to delete source message after move", "error", err)
	}

	return newMsg.UID, nil
}

// CopyMessage copies a message to another mailbox
func (s *MessageStore) CopyMessage(ctx context.Context, srcMailboxID, dstMailboxID uuid.UUID, uid uint32) (uint32, error) {
	// Get message content
	content, err := s.GetMessageContent(ctx, srcMailboxID, uid)
	if err != nil {
		return 0, err
	}

	// Get original message for flags
	origMsg, err := s.GetMessage(ctx, srcMailboxID, uid)
	if err != nil {
		return 0, err
	}

	// Store in destination
	newMsg, err := s.StoreMessage(ctx, dstMailboxID, content, origMsg.Flags)
	if err != nil {
		return 0, err
	}

	return newMsg.UID, nil
}

// scanMessage scans a single message from a row
func (s *MessageStore) scanMessage(row pgx.Row) (*Message, error) {
	var msg Message
	var messageID, inReplyTo, subject, fromAddress, bodyText *string
	var headersJSON []byte
	var date *time.Time

	err := row.Scan(
		&msg.ID, &msg.MailboxID, &msg.UID, &messageID, &inReplyTo, &subject,
		&fromAddress, &msg.ToAddresses, &msg.CcAddresses, &date, &msg.Size,
		&msg.StoragePath, &msg.Flags, &msg.InternalDate, &headersJSON, &bodyText, &msg.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("message not found")
		}
		return nil, fmt.Errorf("failed to scan message: %w", err)
	}

	if messageID != nil {
		msg.MessageID = *messageID
	}
	if inReplyTo != nil {
		msg.InReplyTo = *inReplyTo
	}
	if subject != nil {
		msg.Subject = *subject
	}
	if fromAddress != nil {
		msg.FromAddress = *fromAddress
	}
	if bodyText != nil {
		msg.BodyText = *bodyText
	}
	if date != nil {
		msg.Date = date
	}
	if headersJSON != nil {
		json.Unmarshal(headersJSON, &msg.HeadersJSON)
	}

	return &msg, nil
}

// scanMessages scans multiple messages from rows
func (s *MessageStore) scanMessages(rows pgx.Rows) ([]*Message, error) {
	var messages []*Message
	for rows.Next() {
		var msg Message
		var messageID, inReplyTo, subject, fromAddress, bodyText *string
		var headersJSON []byte
		var date *time.Time

		err := rows.Scan(
			&msg.ID, &msg.MailboxID, &msg.UID, &messageID, &inReplyTo, &subject,
			&fromAddress, &msg.ToAddresses, &msg.CcAddresses, &date, &msg.Size,
			&msg.StoragePath, &msg.Flags, &msg.InternalDate, &headersJSON, &bodyText, &msg.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}

		if messageID != nil {
			msg.MessageID = *messageID
		}
		if inReplyTo != nil {
			msg.InReplyTo = *inReplyTo
		}
		if subject != nil {
			msg.Subject = *subject
		}
		if fromAddress != nil {
			msg.FromAddress = *fromAddress
		}
		if bodyText != nil {
			msg.BodyText = *bodyText
		}
		if date != nil {
			msg.Date = date
		}
		if headersJSON != nil {
			json.Unmarshal(headersJSON, &msg.HeadersJSON)
		}

		messages = append(messages, &msg)
	}
	return messages, nil
}

// parsedEmail contains extracted email metadata
type parsedEmail struct {
	MessageID string
	InReplyTo string
	Subject   string
	From      string
	To        []string
	Cc        []string
	Date      *time.Time
	Headers   map[string]string
	BodyText  string
}

// parseEmail parses an email message and extracts metadata
func (s *MessageStore) parseEmail(content []byte) (*parsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	parsed := &parsedEmail{
		Headers: make(map[string]string),
	}

	// Extract headers
	parsed.MessageID = msg.Header.Get("Message-ID")
	parsed.InReplyTo = msg.Header.Get("In-Reply-To")
	parsed.Subject = decodeHeader(msg.Header.Get("Subject"))
	parsed.From = extractEmailAddress(msg.Header.Get("From"))
	parsed.To = extractEmailAddresses(msg.Header.Get("To"))
	parsed.Cc = extractEmailAddresses(msg.Header.Get("Cc"))

	// Parse date
	if dateStr := msg.Header.Get("Date"); dateStr != "" {
		if t, err := mail.ParseDate(dateStr); err == nil {
			parsed.Date = &t
		}
	}

	// Store important headers
	importantHeaders := []string{
		"From", "To", "Cc", "Bcc", "Subject", "Date",
		"Message-ID", "In-Reply-To", "References",
		"Content-Type", "MIME-Version",
	}
	for _, h := range importantHeaders {
		if v := msg.Header.Get(h); v != "" {
			parsed.Headers[h] = v
		}
	}

	// Extract body text for search
	parsed.BodyText = s.extractBodyText(msg)

	return parsed, nil
}

// extractBodyText extracts plain text from the email body
func (s *MessageStore) extractBodyText(msg *mail.Message) string {
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Try to read as plain text
		body, _ := io.ReadAll(io.LimitReader(msg.Body, 100*1024)) // Limit to 100KB
		return string(body)
	}

	if strings.HasPrefix(mediaType, "text/plain") {
		body, _ := io.ReadAll(io.LimitReader(msg.Body, 100*1024))
		return string(body)
	}

	if strings.HasPrefix(mediaType, "text/html") {
		body, _ := io.ReadAll(io.LimitReader(msg.Body, 100*1024))
		return stripHTML(string(body))
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}

		mr := multipart.NewReader(msg.Body, boundary)
		var textParts []string

		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}

			partType := part.Header.Get("Content-Type")
			if strings.HasPrefix(partType, "text/plain") {
				body, _ := io.ReadAll(io.LimitReader(part, 50*1024))
				textParts = append(textParts, string(body))
			} else if strings.HasPrefix(partType, "text/html") && len(textParts) == 0 {
				body, _ := io.ReadAll(io.LimitReader(part, 50*1024))
				textParts = append(textParts, stripHTML(string(body)))
			}
		}

		return strings.Join(textParts, "\n")
	}

	return ""
}

// getUserInfo retrieves user domain and localpart
func (s *MessageStore) getUserInfo(ctx context.Context, userID uuid.UUID) (*userInfo, error) {
	query := `
		SELECT d.name, u.username
		FROM users u
		JOIN domains d ON d.id = u.domain_id
		WHERE u.id = $1
	`

	var info userInfo
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(&info.Domain, &info.Localpart)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &info, nil
}

// Helper functions

func containsFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

func mergeFlags(existing, new []string) []string {
	flagSet := make(map[string]bool)
	for _, f := range existing {
		flagSet[f] = true
	}
	for _, f := range new {
		flagSet[f] = true
	}

	result := make([]string, 0, len(flagSet))
	for f := range flagSet {
		result = append(result, f)
	}
	return result
}

func removeFlags(existing, toRemove []string) []string {
	removeSet := make(map[string]bool)
	for _, f := range toRemove {
		removeSet[strings.ToLower(f)] = true
	}

	var result []string
	for _, f := range existing {
		if !removeSet[strings.ToLower(f)] {
			result = append(result, f)
		}
	}
	return result
}

func decodeHeader(s string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func extractEmailAddress(s string) string {
	if s == "" {
		return ""
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		// Try to extract just the email part
		s = strings.TrimSpace(s)
		if idx := strings.LastIndex(s, "<"); idx != -1 {
			s = s[idx+1:]
			if idx := strings.Index(s, ">"); idx != -1 {
				s = s[:idx]
			}
		}
		return s
	}
	return addr.Address
}

func extractEmailAddresses(s string) []string {
	if s == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(s)
	if err != nil {
		// Fall back to simple splitting
		parts := strings.Split(s, ",")
		var result []string
		for _, p := range parts {
			if addr := extractEmailAddress(strings.TrimSpace(p)); addr != "" {
				result = append(result, addr)
			}
		}
		return result
	}

	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = addr.Address
	}
	return result
}

func stripHTML(s string) string {
	// Simple HTML tag removal
	var result strings.Builder
	inTag := false

	for _, r := range s {
		if r == '<' {
			inTag = true
		} else if r == '>' {
			inTag = false
		} else if !inTag {
			result.WriteRune(r)
		}
	}

	// Clean up whitespace
	text := result.String()
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// Collapse multiple newlines
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}

	return strings.TrimSpace(text)
}
