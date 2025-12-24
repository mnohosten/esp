package maildir

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StoreResult contains information about a stored message
type StoreResult struct {
	Filename string
	Path     string
	Size     int64
}

// StoreMessage stores a message in the mailbox using the Maildir delivery pattern:
// 1. Write to tmp/ with a unique filename
// 2. Sync the file to ensure durability
// 3. Move (rename) to new/ or cur/ depending on flags
//
// This ensures atomic delivery - the message either appears fully or not at all.
func (m *Maildir) StoreMessage(ctx context.Context, domain, localpart, mailboxName string, content io.Reader, flags []string) (*StoreResult, error) {
	// Generate unique filename
	filename := m.GenerateFilename(flags)

	// Determine paths
	tmpPath := filepath.Join(m.TmpPath(domain, localpart, mailboxName), filename)

	// Determine target directory based on flags
	targetDir := m.GetSubdir(flags)
	var targetPath string
	if targetDir == DirCur {
		targetPath = filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)
	} else {
		targetPath = filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)
	}

	m.logger.Debug("storing message",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"filename", filename,
		"target_dir", targetDir,
	)

	// Step 1: Write to tmp/
	size, err := m.writeToTmp(tmpPath, content)
	if err != nil {
		return nil, fmt.Errorf("failed to write to tmp: %w", err)
	}

	// Step 2: Move from tmp/ to target directory
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Clean up tmp file on failure
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to move message to %s: %w", targetDir, err)
	}

	m.logger.Info("message stored",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"filename", filename,
		"size", size,
	)

	return &StoreResult{
		Filename: filename,
		Path:     targetPath,
		Size:     size,
	}, nil
}

// writeToTmp writes content to a temporary file and syncs it
func (m *Maildir) writeToTmp(path string, content io.Reader) (int64, error) {
	// Create file with restricted permissions
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, m.fileMode)
	if err != nil {
		return 0, fmt.Errorf("failed to create tmp file: %w", err)
	}

	// Copy content
	size, err := io.Copy(f, content)
	if err != nil {
		f.Close()
		os.Remove(path)
		return 0, fmt.Errorf("failed to write content: %w", err)
	}

	// Sync to ensure durability
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return 0, fmt.Errorf("failed to sync file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(path)
		return 0, fmt.Errorf("failed to close file: %w", err)
	}

	return size, nil
}

// StoreMessageBytes is a convenience method that stores a message from a byte slice
func (m *Maildir) StoreMessageBytes(ctx context.Context, domain, localpart, mailboxName string, content []byte, flags []string) (*StoreResult, error) {
	return m.StoreMessage(ctx, domain, localpart, mailboxName, strings.NewReader(string(content)), flags)
}

// GetMessage retrieves a message by filename from a mailbox
// It searches both new/ and cur/ directories
func (m *Maildir) GetMessage(ctx context.Context, domain, localpart, mailboxName, filename string) ([]byte, error) {
	// Try cur/ first (more likely for existing messages)
	curPath := filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)
	content, err := os.ReadFile(curPath)
	if err == nil {
		return content, nil
	}

	// Try new/
	newPath := filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)
	content, err = os.ReadFile(newPath)
	if err == nil {
		return content, nil
	}

	return nil, fmt.Errorf("message not found: %s", filename)
}

// GetMessagePath returns the full path to a message file
// It searches both new/ and cur/ directories
func (m *Maildir) GetMessagePath(ctx context.Context, domain, localpart, mailboxName, filename string) (string, error) {
	// Try cur/ first
	curPath := filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)
	if _, err := os.Stat(curPath); err == nil {
		return curPath, nil
	}

	// Try new/
	newPath := filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)
	if _, err := os.Stat(newPath); err == nil {
		return newPath, nil
	}

	return "", fmt.Errorf("message not found: %s", filename)
}

// GetMessageReader returns a reader for a message file
// Caller is responsible for closing the reader
func (m *Maildir) GetMessageReader(ctx context.Context, domain, localpart, mailboxName, filename string) (io.ReadCloser, error) {
	path, err := m.GetMessagePath(ctx, domain, localpart, mailboxName, filename)
	if err != nil {
		return nil, err
	}

	return os.Open(path)
}

// DeleteMessage removes a message file from a mailbox
func (m *Maildir) DeleteMessage(ctx context.Context, domain, localpart, mailboxName, filename string) error {
	path, err := m.GetMessagePath(ctx, domain, localpart, mailboxName, filename)
	if err != nil {
		return err
	}

	m.logger.Debug("deleting message",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"filename", filename,
	)

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	return nil
}

// DeleteMessages removes multiple message files from a mailbox
func (m *Maildir) DeleteMessages(ctx context.Context, domain, localpart, mailboxName string, filenames []string) error {
	var errs []error
	for _, filename := range filenames {
		if err := m.DeleteMessage(ctx, domain, localpart, mailboxName, filename); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete %d messages: %v", len(errs), errs[0])
	}

	return nil
}

// MoveMessage moves a message between mailboxes or between new/cur within the same mailbox
func (m *Maildir) MoveMessage(ctx context.Context, domain, localpart string, srcMailbox, dstMailbox, filename string) error {
	srcPath, err := m.GetMessagePath(ctx, domain, localpart, srcMailbox, filename)
	if err != nil {
		return fmt.Errorf("source message not found: %w", err)
	}

	// Determine destination - messages being moved go to cur/ (they've been "seen" by the move operation)
	dstPath := filepath.Join(m.CurPath(domain, localpart, dstMailbox), filename)

	m.logger.Debug("moving message",
		"domain", domain,
		"localpart", localpart,
		"src_mailbox", srcMailbox,
		"dst_mailbox", dstMailbox,
		"filename", filename,
	)

	// Try rename first (fastest if on same filesystem)
	if err := os.Rename(srcPath, dstPath); err == nil {
		return nil
	}

	// Fall back to copy+delete for cross-filesystem moves
	return m.copyAndDelete(srcPath, dstPath)
}

// MoveToNew moves a message from cur/ to new/ (mark as unread)
func (m *Maildir) MoveToNew(ctx context.Context, domain, localpart, mailboxName, filename string) error {
	curPath := filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)
	newPath := filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)

	// Check if message is in cur/
	if _, err := os.Stat(curPath); err != nil {
		return fmt.Errorf("message not in cur/: %s", filename)
	}

	return os.Rename(curPath, newPath)
}

// MoveToCur moves a message from new/ to cur/ (mark as read/seen)
func (m *Maildir) MoveToCur(ctx context.Context, domain, localpart, mailboxName, filename string) error {
	newPath := filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)
	curPath := filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)

	// Check if message is in new/
	if _, err := os.Stat(newPath); err != nil {
		return fmt.Errorf("message not in new/: %s", filename)
	}

	return os.Rename(newPath, curPath)
}

// CopyMessage copies a message to another mailbox
func (m *Maildir) CopyMessage(ctx context.Context, domain, localpart string, srcMailbox, dstMailbox, srcFilename string) (string, error) {
	srcPath, err := m.GetMessagePath(ctx, domain, localpart, srcMailbox, srcFilename)
	if err != nil {
		return "", fmt.Errorf("source message not found: %w", err)
	}

	// Generate new filename for the copy
	flags := m.DecodeFlags(srcFilename)
	newFilename := m.GenerateFilename(flags)

	// Copies go to cur/
	dstPath := filepath.Join(m.CurPath(domain, localpart, dstMailbox), newFilename)

	m.logger.Debug("copying message",
		"domain", domain,
		"localpart", localpart,
		"src_mailbox", srcMailbox,
		"dst_mailbox", dstMailbox,
		"src_filename", srcFilename,
		"dst_filename", newFilename,
	)

	if err := m.copyFile(srcPath, dstPath); err != nil {
		return "", fmt.Errorf("failed to copy message: %w", err)
	}

	return newFilename, nil
}

// copyFile copies a file from src to dst
func (m *Maildir) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, m.fileMode)
	if err != nil {
		return err
	}

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		os.Remove(dst)
		return err
	}

	if err := dstFile.Sync(); err != nil {
		dstFile.Close()
		os.Remove(dst)
		return err
	}

	return dstFile.Close()
}

// copyAndDelete copies a file then deletes the source (for cross-filesystem moves)
func (m *Maildir) copyAndDelete(src, dst string) error {
	if err := m.copyFile(src, dst); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}

	if err := os.Remove(src); err != nil {
		// Try to clean up destination
		os.Remove(dst)
		return fmt.Errorf("delete source failed: %w", err)
	}

	return nil
}

// UpdateMessageFlags updates the flags of a message by renaming the file
func (m *Maildir) UpdateMessageFlags(ctx context.Context, domain, localpart, mailboxName, filename string, newFlags []string) (string, error) {
	path, err := m.GetMessagePath(ctx, domain, localpart, mailboxName, filename)
	if err != nil {
		return "", err
	}

	// Generate new filename with updated flags
	newFilename := m.UpdateFilenameFlags(filename, newFlags)
	if newFilename == filename {
		return filename, nil // No change needed
	}

	// Determine target directory based on Seen flag
	targetDir := m.GetSubdir(newFlags)
	var newPath string
	if targetDir == DirCur {
		newPath = filepath.Join(m.CurPath(domain, localpart, mailboxName), newFilename)
	} else {
		newPath = filepath.Join(m.NewPath(domain, localpart, mailboxName), newFilename)
	}

	m.logger.Debug("updating message flags",
		"domain", domain,
		"localpart", localpart,
		"mailbox", mailboxName,
		"old_filename", filename,
		"new_filename", newFilename,
	)

	if err := os.Rename(path, newPath); err != nil {
		return "", fmt.Errorf("failed to rename message: %w", err)
	}

	return newFilename, nil
}

// ListMessages returns all message filenames in a mailbox
// Returns filenames from both new/ and cur/ directories
func (m *Maildir) ListMessages(ctx context.Context, domain, localpart, mailboxName string) ([]string, error) {
	var messages []string

	// Read new/ directory
	newPath := m.NewPath(domain, localpart, mailboxName)
	newEntries, err := os.ReadDir(newPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read new/: %w", err)
	}
	for _, entry := range newEntries {
		if !entry.IsDir() {
			messages = append(messages, entry.Name())
		}
	}

	// Read cur/ directory
	curPath := m.CurPath(domain, localpart, mailboxName)
	curEntries, err := os.ReadDir(curPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read cur/: %w", err)
	}
	for _, entry := range curEntries {
		if !entry.IsDir() {
			messages = append(messages, entry.Name())
		}
	}

	return messages, nil
}

// MessageInfo contains information about a message file
type MessageInfo struct {
	Filename     string
	Path         string
	Size         int64
	ModTime      time.Time
	Flags        []string
	InNewDir     bool // true if in new/, false if in cur/
}

// GetMessageInfo returns detailed information about a message
func (m *Maildir) GetMessageInfo(ctx context.Context, domain, localpart, mailboxName, filename string) (*MessageInfo, error) {
	// Try cur/ first
	curPath := filepath.Join(m.CurPath(domain, localpart, mailboxName), filename)
	if info, err := os.Stat(curPath); err == nil {
		return &MessageInfo{
			Filename: filename,
			Path:     curPath,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Flags:    m.DecodeFlags(filename),
			InNewDir: false,
		}, nil
	}

	// Try new/
	newPath := filepath.Join(m.NewPath(domain, localpart, mailboxName), filename)
	if info, err := os.Stat(newPath); err == nil {
		return &MessageInfo{
			Filename: filename,
			Path:     newPath,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Flags:    m.DecodeFlags(filename),
			InNewDir: true,
		}, nil
	}

	return nil, fmt.Errorf("message not found: %s", filename)
}

// ListMessagesInfo returns information about all messages in a mailbox
func (m *Maildir) ListMessagesInfo(ctx context.Context, domain, localpart, mailboxName string) ([]*MessageInfo, error) {
	var messages []*MessageInfo

	// Read new/ directory
	newPath := m.NewPath(domain, localpart, mailboxName)
	newEntries, err := os.ReadDir(newPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read new/: %w", err)
	}
	for _, entry := range newEntries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		messages = append(messages, &MessageInfo{
			Filename: entry.Name(),
			Path:     filepath.Join(newPath, entry.Name()),
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Flags:    m.DecodeFlags(entry.Name()),
			InNewDir: true,
		})
	}

	// Read cur/ directory
	curPath := m.CurPath(domain, localpart, mailboxName)
	curEntries, err := os.ReadDir(curPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read cur/: %w", err)
	}
	for _, entry := range curEntries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		messages = append(messages, &MessageInfo{
			Filename: entry.Name(),
			Path:     filepath.Join(curPath, entry.Name()),
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Flags:    m.DecodeFlags(entry.Name()),
			InNewDir: false,
		})
	}

	return messages, nil
}

// CleanupTmp removes old files from tmp/ directory
// Files older than maxAge are considered stale delivery attempts
func (m *Maildir) CleanupTmp(ctx context.Context, domain, localpart, mailboxName string, maxAge time.Duration) (int, error) {
	tmpPath := m.TmpPath(domain, localpart, mailboxName)
	entries, err := os.ReadDir(tmpPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read tmp/: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	deleted := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(tmpPath, entry.Name())
			if err := os.Remove(path); err == nil {
				deleted++
				m.logger.Debug("cleaned up stale tmp file",
					"path", path,
					"mod_time", info.ModTime(),
				)
			}
		}
	}

	return deleted, nil
}
