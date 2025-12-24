package maildir

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mnohosten/esp/internal/config"
	"github.com/mnohosten/esp/internal/logging"
)

func setupTestMaildir(t *testing.T) (*Maildir, string) {
	t.Helper()
	tmpDir := t.TempDir()
	logger := logging.New(config.LoggingConfig{Level: "error", Format: "text"})

	cfg := config.MaildirConfig{
		BasePath: tmpDir,
		DirMode:  0750,
		FileMode: 0640,
	}

	m, err := New(cfg, nil, "mail.example.com", logger)
	if err != nil {
		t.Fatalf("Failed to create Maildir: %v", err)
	}

	// Create user maildir
	ctx := context.Background()
	if err := m.CreateUserMaildir(ctx, "example.com", "testuser"); err != nil {
		t.Fatalf("Failed to create user maildir: %v", err)
	}

	return m, tmpDir
}

func TestMaildir_StoreMessage(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nThis is a test message."

	// Store message without flags (should go to new/)
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	if result.Filename == "" {
		t.Error("StoreMessage() returned empty filename")
	}
	if result.Size != int64(len(testContent)) {
		t.Errorf("StoreMessage() size = %d, want %d", result.Size, len(testContent))
	}

	// Verify file is in new/
	newPath := m.NewPath("example.com", "testuser", "INBOX")
	if _, err := os.Stat(filepath.Join(newPath, result.Filename)); err != nil {
		t.Error("Message should be in new/ directory")
	}

	// Store message with Seen flag (should go to cur/)
	result2, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), []string{"\\Seen"})
	if err != nil {
		t.Fatalf("StoreMessage() with Seen flag error = %v", err)
	}

	// Verify file is in cur/
	curPath := m.CurPath("example.com", "testuser", "INBOX")
	if _, err := os.Stat(filepath.Join(curPath, result2.Filename)); err != nil {
		t.Error("Message with \\Seen flag should be in cur/ directory")
	}

	// Verify flags in filename
	if !strings.HasSuffix(result2.Filename, ":2,S") {
		t.Errorf("Filename should end with :2,S, got %s", result2.Filename)
	}
}

func TestMaildir_StoreMessageBytes(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := []byte("Subject: Test\r\n\r\nThis is a test message.")

	result, err := m.StoreMessageBytes(ctx, "example.com", "testuser", "INBOX", testContent, nil)
	if err != nil {
		t.Fatalf("StoreMessageBytes() error = %v", err)
	}

	if result.Size != int64(len(testContent)) {
		t.Errorf("StoreMessageBytes() size = %d, want %d", result.Size, len(testContent))
	}
}

func TestMaildir_GetMessage(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nThis is a test message."

	// Store a message
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Retrieve the message
	content, err := m.GetMessage(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("GetMessage() error = %v", err)
	}

	if string(content) != testContent {
		t.Errorf("GetMessage() content mismatch")
	}

	// Try to get non-existent message
	_, err = m.GetMessage(ctx, "example.com", "testuser", "INBOX", "nonexistent")
	if err == nil {
		t.Error("GetMessage() should return error for non-existent message")
	}
}

func TestMaildir_GetMessagePath(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	path, err := m.GetMessagePath(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("GetMessagePath() error = %v", err)
	}

	if !strings.Contains(path, result.Filename) {
		t.Errorf("GetMessagePath() should contain filename")
	}
}

func TestMaildir_GetMessageReader(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	reader, err := m.GetMessageReader(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("GetMessageReader() error = %v", err)
	}
	defer reader.Close()

	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	if string(buf[:n]) != testContent {
		t.Error("GetMessageReader() content mismatch")
	}
}

func TestMaildir_DeleteMessage(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	// Store a message
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Delete the message
	err = m.DeleteMessage(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("DeleteMessage() error = %v", err)
	}

	// Verify it's gone
	_, err = m.GetMessage(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err == nil {
		t.Error("Message should be deleted")
	}

	// Delete non-existent message should error
	err = m.DeleteMessage(ctx, "example.com", "testuser", "INBOX", "nonexistent")
	if err == nil {
		t.Error("DeleteMessage() should return error for non-existent message")
	}
}

func TestMaildir_DeleteMessages(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	// Store multiple messages
	var filenames []string
	for i := 0; i < 3; i++ {
		result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
			strings.NewReader("Test message"), nil)
		if err != nil {
			t.Fatalf("StoreMessage() error = %v", err)
		}
		filenames = append(filenames, result.Filename)
	}

	// Delete all messages
	err := m.DeleteMessages(ctx, "example.com", "testuser", "INBOX", filenames)
	if err != nil {
		t.Fatalf("DeleteMessages() error = %v", err)
	}

	// Verify all are gone
	for _, fn := range filenames {
		_, err = m.GetMessage(ctx, "example.com", "testuser", "INBOX", fn)
		if err == nil {
			t.Error("Message should be deleted")
		}
	}
}

func TestMaildir_MoveMessage(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	// Store a message in INBOX
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Move to Sent
	err = m.MoveMessage(ctx, "example.com", "testuser", "INBOX", "Sent", result.Filename)
	if err != nil {
		t.Fatalf("MoveMessage() error = %v", err)
	}

	// Verify message is in Sent
	_, err = m.GetMessage(ctx, "example.com", "testuser", "Sent", result.Filename)
	if err != nil {
		t.Error("Message should be in Sent folder")
	}

	// Verify message is not in INBOX
	_, err = m.GetMessage(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err == nil {
		t.Error("Message should not be in INBOX anymore")
	}
}

func TestMaildir_MoveToCurAndNew(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	// Store a message (goes to new/)
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Move to cur/
	err = m.MoveToCur(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("MoveToCur() error = %v", err)
	}

	// Verify it's in cur/
	curPath := filepath.Join(m.CurPath("example.com", "testuser", "INBOX"), result.Filename)
	if _, err := os.Stat(curPath); err != nil {
		t.Error("Message should be in cur/")
	}

	// Move back to new/
	err = m.MoveToNew(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("MoveToNew() error = %v", err)
	}

	// Verify it's in new/
	newPath := filepath.Join(m.NewPath("example.com", "testuser", "INBOX"), result.Filename)
	if _, err := os.Stat(newPath); err != nil {
		t.Error("Message should be in new/")
	}
}

func TestMaildir_CopyMessage(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	// Store a message in INBOX
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), []string{"\\Seen", "\\Flagged"})
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Copy to Sent
	newFilename, err := m.CopyMessage(ctx, "example.com", "testuser", "INBOX", "Sent", result.Filename)
	if err != nil {
		t.Fatalf("CopyMessage() error = %v", err)
	}

	// Verify copy is in Sent
	content, err := m.GetMessage(ctx, "example.com", "testuser", "Sent", newFilename)
	if err != nil {
		t.Error("Copy should be in Sent folder")
	}
	if string(content) != testContent {
		t.Error("Copy content should match original")
	}

	// Verify original still in INBOX
	_, err = m.GetMessage(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Error("Original should still be in INBOX")
	}

	// Verify copy has same flags
	copyFlags := m.DecodeFlags(newFilename)
	if len(copyFlags) != 2 {
		t.Errorf("Copy should have same flags, got %v", copyFlags)
	}
}

func TestMaildir_UpdateMessageFlags(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	// Store a message without flags
	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), nil)
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// Add Seen flag
	newFilename, err := m.UpdateMessageFlags(ctx, "example.com", "testuser", "INBOX",
		result.Filename, []string{"\\Seen"})
	if err != nil {
		t.Fatalf("UpdateMessageFlags() error = %v", err)
	}

	// Verify new filename has Seen flag
	if !strings.HasSuffix(newFilename, ":2,S") {
		t.Errorf("New filename should have S flag, got %s", newFilename)
	}

	// Verify message moved to cur/
	curPath := filepath.Join(m.CurPath("example.com", "testuser", "INBOX"), newFilename)
	if _, err := os.Stat(curPath); err != nil {
		t.Error("Message with \\Seen flag should be in cur/")
	}

	// Add more flags
	newFilename2, err := m.UpdateMessageFlags(ctx, "example.com", "testuser", "INBOX",
		newFilename, []string{"\\Seen", "\\Flagged", "\\Answered"})
	if err != nil {
		t.Fatalf("UpdateMessageFlags() error = %v", err)
	}

	if !strings.HasSuffix(newFilename2, ":2,FRS") {
		t.Errorf("New filename should have FRS flags, got %s", newFilename2)
	}
}

func TestMaildir_ListMessages(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	// Store some messages
	for i := 0; i < 3; i++ {
		_, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
			strings.NewReader("Test message"), nil)
		if err != nil {
			t.Fatalf("StoreMessage() error = %v", err)
		}
	}

	// Store one with Seen flag (goes to cur/)
	_, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader("Seen message"), []string{"\\Seen"})
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	// List all messages
	messages, err := m.ListMessages(ctx, "example.com", "testuser", "INBOX")
	if err != nil {
		t.Fatalf("ListMessages() error = %v", err)
	}

	if len(messages) != 4 {
		t.Errorf("ListMessages() returned %d messages, want 4", len(messages))
	}
}

func TestMaildir_GetMessageInfo(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	testContent := "Subject: Test\r\n\r\nTest body."

	result, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader(testContent), []string{"\\Seen", "\\Flagged"})
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	info, err := m.GetMessageInfo(ctx, "example.com", "testuser", "INBOX", result.Filename)
	if err != nil {
		t.Fatalf("GetMessageInfo() error = %v", err)
	}

	if info.Filename != result.Filename {
		t.Errorf("GetMessageInfo() filename mismatch")
	}
	if info.Size != int64(len(testContent)) {
		t.Errorf("GetMessageInfo() size = %d, want %d", info.Size, len(testContent))
	}
	if len(info.Flags) != 2 {
		t.Errorf("GetMessageInfo() flags = %v, want 2 flags", info.Flags)
	}
	if info.InNewDir {
		t.Error("GetMessageInfo() should report message in cur/, not new/")
	}
}

func TestMaildir_ListMessagesInfo(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	// Store messages in new/
	for i := 0; i < 2; i++ {
		_, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
			strings.NewReader("Test message"), nil)
		if err != nil {
			t.Fatalf("StoreMessage() error = %v", err)
		}
	}

	// Store message in cur/
	_, err := m.StoreMessage(ctx, "example.com", "testuser", "INBOX",
		strings.NewReader("Seen message"), []string{"\\Seen"})
	if err != nil {
		t.Fatalf("StoreMessage() error = %v", err)
	}

	infos, err := m.ListMessagesInfo(ctx, "example.com", "testuser", "INBOX")
	if err != nil {
		t.Fatalf("ListMessagesInfo() error = %v", err)
	}

	if len(infos) != 3 {
		t.Errorf("ListMessagesInfo() returned %d messages, want 3", len(infos))
	}

	// Count new/ vs cur/
	newCount := 0
	curCount := 0
	for _, info := range infos {
		if info.InNewDir {
			newCount++
		} else {
			curCount++
		}
	}

	if newCount != 2 || curCount != 1 {
		t.Errorf("Expected 2 in new/ and 1 in cur/, got %d and %d", newCount, curCount)
	}
}

func TestMaildir_CleanupTmp(t *testing.T) {
	m, _ := setupTestMaildir(t)
	ctx := context.Background()

	// Create a stale file in tmp/
	tmpPath := m.TmpPath("example.com", "testuser", "INBOX")
	staleFile := filepath.Join(tmpPath, "stale_file")
	if err := os.WriteFile(staleFile, []byte("stale"), 0640); err != nil {
		t.Fatalf("Failed to create stale file: %v", err)
	}

	// Set modification time to 2 hours ago
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(staleFile, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set file time: %v", err)
	}

	// Create a fresh file
	freshFile := filepath.Join(tmpPath, "fresh_file")
	if err := os.WriteFile(freshFile, []byte("fresh"), 0640); err != nil {
		t.Fatalf("Failed to create fresh file: %v", err)
	}

	// Cleanup files older than 1 hour
	deleted, err := m.CleanupTmp(ctx, "example.com", "testuser", "INBOX", time.Hour)
	if err != nil {
		t.Fatalf("CleanupTmp() error = %v", err)
	}

	if deleted != 1 {
		t.Errorf("CleanupTmp() deleted %d files, want 1", deleted)
	}

	// Verify stale file is gone
	if _, err := os.Stat(staleFile); !os.IsNotExist(err) {
		t.Error("Stale file should be deleted")
	}

	// Verify fresh file still exists
	if _, err := os.Stat(freshFile); err != nil {
		t.Error("Fresh file should still exist")
	}
}
