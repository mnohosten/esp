package maildir

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mnohosten/esp/internal/config"
	"github.com/mnohosten/esp/internal/database"
)

// Standard Maildir subdirectories
const (
	DirNew = "new" // Newly delivered messages, not yet seen
	DirCur = "cur" // Messages that have been seen/accessed
	DirTmp = "tmp" // Temporary directory for atomic writes
)

// Standard special-use mailbox names (IMAP)
const (
	SpecialUseInbox   = "INBOX"
	SpecialUseSent    = "\\Sent"
	SpecialUseDrafts  = "\\Drafts"
	SpecialUseTrash   = "\\Trash"
	SpecialUseJunk    = "\\Junk"
	SpecialUseArchive = "\\Archive"
)

// Maildir flags as encoded in filenames
const (
	FlagDraft   = 'D' // Draft
	FlagFlagged = 'F' // Flagged/Important
	FlagPassed  = 'P' // Passed (forwarded)
	FlagReplied = 'R' // Replied
	FlagSeen    = 'S' // Seen/Read
	FlagTrashed = 'T' // Trashed
)

// IMAP flags to Maildir flag mapping
var imapToMaildirFlag = map[string]rune{
	"\\Draft":   FlagDraft,
	"\\Flagged": FlagFlagged,
	"$Forwarded": FlagPassed,
	"\\Answered": FlagReplied,
	"\\Seen":    FlagSeen,
	"\\Deleted": FlagTrashed,
}

// Maildir flag to IMAP flag mapping
var maildirToIMAPFlag = map[rune]string{
	FlagDraft:   "\\Draft",
	FlagFlagged: "\\Flagged",
	FlagPassed:  "$Forwarded",
	FlagReplied: "\\Answered",
	FlagSeen:    "\\Seen",
	FlagTrashed: "\\Deleted",
}

// Maildir implements message storage using Maildir format
type Maildir struct {
	basePath string
	dirMode  fs.FileMode
	fileMode fs.FileMode
	db       *database.DB
	logger   *slog.Logger
	hostname string

	// Counter for unique filename generation
	deliveryCounter uint64
	counterMu       sync.Mutex
}

// New creates a new Maildir store
func New(cfg config.MaildirConfig, db *database.DB, hostname string, logger *slog.Logger) (*Maildir, error) {
	if cfg.BasePath == "" {
		return nil, fmt.Errorf("maildir base path is required")
	}

	dirMode := fs.FileMode(cfg.DirMode)
	if dirMode == 0 {
		dirMode = 0750
	}

	fileMode := fs.FileMode(cfg.FileMode)
	if fileMode == 0 {
		fileMode = 0640
	}

	m := &Maildir{
		basePath: cfg.BasePath,
		dirMode:  dirMode,
		fileMode: fileMode,
		db:       db,
		logger:   logger.With("component", "maildir"),
		hostname: hostname,
	}

	// Ensure base directory exists
	if err := m.ensureDir(cfg.BasePath); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return m, nil
}

// ensureDir creates a directory if it doesn't exist
func (m *Maildir) ensureDir(path string) error {
	return os.MkdirAll(path, m.dirMode)
}

// UserMaildirPath returns the path to a user's maildir root
// Structure: basePath/domain/localpart/
func (m *Maildir) UserMaildirPath(domain, localpart string) string {
	return filepath.Join(m.basePath, domain, localpart)
}

// MailboxPath returns the path to a specific mailbox
// INBOX is the root, other mailboxes are prefixed with '.'
// Structure: basePath/domain/localpart/.FolderName/
func (m *Maildir) MailboxPath(domain, localpart, mailboxName string) string {
	userPath := m.UserMaildirPath(domain, localpart)

	if mailboxName == SpecialUseInbox || mailboxName == "INBOX" {
		return userPath
	}

	// Convert hierarchy delimiter '/' to '.' for filesystem
	// e.g., "Folder/Subfolder" becomes ".Folder.Subfolder"
	fsName := strings.ReplaceAll(mailboxName, "/", ".")
	return filepath.Join(userPath, "."+fsName)
}

// CreateUserMaildir creates the initial maildir structure for a new user
// Creates: tmp/, new/, cur/ in the INBOX and default special folders
func (m *Maildir) CreateUserMaildir(ctx context.Context, domain, localpart string) error {
	userPath := m.UserMaildirPath(domain, localpart)

	m.logger.Info("creating user maildir",
		"domain", domain,
		"localpart", localpart,
		"path", userPath,
	)

	// Create INBOX (root maildir)
	if err := m.createMaildirDirs(userPath); err != nil {
		return fmt.Errorf("failed to create INBOX: %w", err)
	}

	// Create default special-use mailboxes
	defaultMailboxes := []string{
		"Sent",
		"Drafts",
		"Trash",
		"Junk",
	}

	for _, mb := range defaultMailboxes {
		mbPath := m.MailboxPath(domain, localpart, mb)
		if err := m.createMaildirDirs(mbPath); err != nil {
			return fmt.Errorf("failed to create %s mailbox: %w", mb, err)
		}
	}

	return nil
}

// createMaildirDirs creates the standard maildir subdirectories (tmp, new, cur)
func (m *Maildir) createMaildirDirs(path string) error {
	for _, dir := range []string{DirTmp, DirNew, DirCur} {
		dirPath := filepath.Join(path, dir)
		if err := m.ensureDir(dirPath); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	return nil
}

// CreateMailbox creates a new mailbox directory structure
func (m *Maildir) CreateMailbox(ctx context.Context, domain, localpart, mailboxName string) error {
	if mailboxName == "" || mailboxName == SpecialUseInbox || mailboxName == "INBOX" {
		return fmt.Errorf("cannot create INBOX, it already exists")
	}

	mbPath := m.MailboxPath(domain, localpart, mailboxName)

	m.logger.Info("creating mailbox",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"path", mbPath,
	)

	// Check if mailbox already exists
	if _, err := os.Stat(mbPath); err == nil {
		return fmt.Errorf("mailbox already exists: %s", mailboxName)
	}

	return m.createMaildirDirs(mbPath)
}

// DeleteMailbox removes a mailbox and all its messages
func (m *Maildir) DeleteMailbox(ctx context.Context, domain, localpart, mailboxName string) error {
	if mailboxName == "" || mailboxName == SpecialUseInbox || mailboxName == "INBOX" {
		return fmt.Errorf("cannot delete INBOX")
	}

	mbPath := m.MailboxPath(domain, localpart, mailboxName)

	m.logger.Info("deleting mailbox",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"path", mbPath,
	)

	return os.RemoveAll(mbPath)
}

// RenameMailbox renames a mailbox
func (m *Maildir) RenameMailbox(ctx context.Context, domain, localpart, oldName, newName string) error {
	if oldName == SpecialUseInbox || oldName == "INBOX" {
		return fmt.Errorf("cannot rename INBOX")
	}
	if newName == SpecialUseInbox || newName == "INBOX" {
		return fmt.Errorf("cannot rename to INBOX")
	}

	oldPath := m.MailboxPath(domain, localpart, oldName)
	newPath := m.MailboxPath(domain, localpart, newName)

	m.logger.Info("renaming mailbox",
		"domain", domain,
		"localpart", localpart,
		"old_name", oldName,
		"new_name", newName,
	)

	// Check source exists
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return fmt.Errorf("mailbox does not exist: %s", oldName)
	}

	// Check destination doesn't exist
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("mailbox already exists: %s", newName)
	}

	// Ensure parent directory exists for nested mailboxes
	if err := m.ensureDir(filepath.Dir(newPath)); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	return os.Rename(oldPath, newPath)
}

// ListMailboxes returns all mailboxes for a user
func (m *Maildir) ListMailboxes(ctx context.Context, domain, localpart string) ([]string, error) {
	userPath := m.UserMaildirPath(domain, localpart)

	entries, err := os.ReadDir(userPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read user directory: %w", err)
	}

	mailboxes := []string{"INBOX"}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Maildir folders start with '.'
		if !strings.HasPrefix(name, ".") {
			continue
		}

		// Skip standard Maildir subdirs
		if name == "."+DirTmp || name == "."+DirNew || name == "."+DirCur {
			continue
		}

		// Convert filesystem name back to IMAP name
		// ".Folder.Subfolder" becomes "Folder/Subfolder"
		mbName := strings.TrimPrefix(name, ".")
		mbName = strings.ReplaceAll(mbName, ".", "/")
		mailboxes = append(mailboxes, mbName)
	}

	sort.Strings(mailboxes[1:]) // Keep INBOX first, sort the rest
	return mailboxes, nil
}

// MailboxExists checks if a mailbox exists
func (m *Maildir) MailboxExists(ctx context.Context, domain, localpart, mailboxName string) (bool, error) {
	mbPath := m.MailboxPath(domain, localpart, mailboxName)
	info, err := os.Stat(mbPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// GenerateFilename generates a unique Maildir filename
// Format: timestamp.uniqueId.hostname:2,flags
func (m *Maildir) GenerateFilename(flags []string) string {
	now := time.Now()

	// Get unique counter
	counter := atomic.AddUint64(&m.deliveryCounter, 1)

	// Build unique ID: timestamp.microsecondsP<pid>Q<counter>
	uniqueID := fmt.Sprintf("%d.M%dP%dQ%d",
		now.Unix(),
		now.Nanosecond()/1000,
		os.Getpid(),
		counter,
	)

	// Encode flags
	flagStr := m.EncodeFlags(flags)

	if flagStr == "" {
		return fmt.Sprintf("%s.%s:2,", uniqueID, m.hostname)
	}
	return fmt.Sprintf("%s.%s:2,%s", uniqueID, m.hostname, flagStr)
}

// EncodeFlags converts IMAP flags to Maildir filename flag suffix
// Flags are sorted alphabetically: D, F, P, R, S, T
func (m *Maildir) EncodeFlags(imapFlags []string) string {
	var flags []rune

	for _, f := range imapFlags {
		if r, ok := imapToMaildirFlag[f]; ok {
			flags = append(flags, r)
		}
	}

	// Sort flags alphabetically
	sort.Slice(flags, func(i, j int) bool {
		return flags[i] < flags[j]
	})

	// Remove duplicates
	seen := make(map[rune]bool)
	unique := flags[:0]
	for _, f := range flags {
		if !seen[f] {
			seen[f] = true
			unique = append(unique, f)
		}
	}

	return string(unique)
}

// DecodeFlags converts Maildir filename flags to IMAP flags
func (m *Maildir) DecodeFlags(filename string) []string {
	// Find flag portion after ":2,"
	idx := strings.LastIndex(filename, ":2,")
	if idx == -1 {
		return nil
	}

	flagStr := filename[idx+3:]
	var flags []string

	for _, r := range flagStr {
		if f, ok := maildirToIMAPFlag[r]; ok {
			flags = append(flags, f)
		}
	}

	return flags
}

// UpdateFilenameFlags updates the flags portion of a filename
func (m *Maildir) UpdateFilenameFlags(filename string, newFlags []string) string {
	// Find the base part before ":2,"
	idx := strings.LastIndex(filename, ":2,")
	var base string
	if idx == -1 {
		// No info portion, filename is the base
		base = filename
	} else {
		base = filename[:idx]
	}

	flagStr := m.EncodeFlags(newFlags)
	return fmt.Sprintf("%s:2,%s", base, flagStr)
}

// GetSubdir returns the appropriate subdirectory (new/cur) based on flags
// Messages with \Seen flag go to cur/, others to new/
func (m *Maildir) GetSubdir(flags []string) string {
	for _, f := range flags {
		if f == "\\Seen" {
			return DirCur
		}
	}
	return DirNew
}

// TmpPath returns the tmp directory path for a mailbox
func (m *Maildir) TmpPath(domain, localpart, mailboxName string) string {
	return filepath.Join(m.MailboxPath(domain, localpart, mailboxName), DirTmp)
}

// NewPath returns the new directory path for a mailbox
func (m *Maildir) NewPath(domain, localpart, mailboxName string) string {
	return filepath.Join(m.MailboxPath(domain, localpart, mailboxName), DirNew)
}

// CurPath returns the cur directory path for a mailbox
func (m *Maildir) CurPath(domain, localpart, mailboxName string) string {
	return filepath.Join(m.MailboxPath(domain, localpart, mailboxName), DirCur)
}

// BasePath returns the base storage path
func (m *Maildir) BasePath() string {
	return m.basePath
}

// SpecialUseFolder returns the mailbox name for a special-use attribute
func SpecialUseFolder(specialUse string) string {
	switch specialUse {
	case SpecialUseSent:
		return "Sent"
	case SpecialUseDrafts:
		return "Drafts"
	case SpecialUseTrash:
		return "Trash"
	case SpecialUseJunk:
		return "Junk"
	case SpecialUseArchive:
		return "Archive"
	default:
		return ""
	}
}

// GetSpecialUse returns the special-use attribute for a mailbox name
func GetSpecialUse(mailboxName string) string {
	switch strings.ToLower(mailboxName) {
	case "sent", "sent items", "sent messages":
		return SpecialUseSent
	case "drafts", "draft":
		return SpecialUseDrafts
	case "trash", "deleted", "deleted items", "deleted messages":
		return SpecialUseTrash
	case "junk", "spam", "bulk mail":
		return SpecialUseJunk
	case "archive", "archives":
		return SpecialUseArchive
	case "inbox":
		return SpecialUseInbox
	default:
		return ""
	}
}
