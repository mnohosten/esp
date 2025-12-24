package maildir

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mnohosten/esp/internal/config"
	"github.com/mnohosten/esp/internal/logging"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()
	logger := logging.New(config.LoggingConfig{Level: "error", Format: "text"})

	tests := []struct {
		name    string
		cfg     config.MaildirConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: config.MaildirConfig{
				BasePath: tmpDir,
				DirMode:  0750,
				FileMode: 0640,
			},
			wantErr: false,
		},
		{
			name: "missing base path",
			cfg: config.MaildirConfig{
				BasePath: "",
			},
			wantErr: true,
		},
		{
			name: "default modes",
			cfg: config.MaildirConfig{
				BasePath: tmpDir,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.cfg, nil, "mail.example.com", logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && m == nil {
				t.Error("New() returned nil without error")
			}
		})
	}
}

func TestMaildir_UserMaildirPath(t *testing.T) {
	tmpDir := t.TempDir()
	m := &Maildir{basePath: tmpDir}

	path := m.UserMaildirPath("example.com", "user")
	expected := filepath.Join(tmpDir, "example.com", "user")

	if path != expected {
		t.Errorf("UserMaildirPath() = %v, want %v", path, expected)
	}
}

func TestMaildir_MailboxPath(t *testing.T) {
	tmpDir := t.TempDir()
	m := &Maildir{basePath: tmpDir}

	tests := []struct {
		name        string
		mailboxName string
		wantSuffix  string
	}{
		{
			name:        "INBOX",
			mailboxName: "INBOX",
			wantSuffix:  "example.com/user",
		},
		{
			name:        "Sent",
			mailboxName: "Sent",
			wantSuffix:  "example.com/user/.Sent",
		},
		{
			name:        "Nested folder",
			mailboxName: "Work/Projects",
			wantSuffix:  "example.com/user/.Work.Projects",
		},
		{
			name:        "Deeply nested",
			mailboxName: "Work/Projects/2024",
			wantSuffix:  "example.com/user/.Work.Projects.2024",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := m.MailboxPath("example.com", "user", tt.mailboxName)
			if !strings.HasSuffix(path, tt.wantSuffix) {
				t.Errorf("MailboxPath() = %v, want suffix %v", path, tt.wantSuffix)
			}
		})
	}
}

func TestMaildir_CreateUserMaildir(t *testing.T) {
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

	ctx := context.Background()
	err = m.CreateUserMaildir(ctx, "example.com", "testuser")
	if err != nil {
		t.Fatalf("CreateUserMaildir() error = %v", err)
	}

	// Verify INBOX directories
	userPath := m.UserMaildirPath("example.com", "testuser")
	for _, dir := range []string{DirTmp, DirNew, DirCur} {
		dirPath := filepath.Join(userPath, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Errorf("INBOX %s directory not created", dir)
		}
	}

	// Verify special-use mailboxes
	for _, mb := range []string{"Sent", "Drafts", "Trash", "Junk"} {
		mbPath := m.MailboxPath("example.com", "testuser", mb)
		for _, dir := range []string{DirTmp, DirNew, DirCur} {
			dirPath := filepath.Join(mbPath, dir)
			if _, err := os.Stat(dirPath); os.IsNotExist(err) {
				t.Errorf("%s/%s directory not created", mb, dir)
			}
		}
	}
}

func TestMaildir_CreateDeleteMailbox(t *testing.T) {
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

	ctx := context.Background()

	// First create user maildir
	err = m.CreateUserMaildir(ctx, "example.com", "testuser")
	if err != nil {
		t.Fatalf("CreateUserMaildir() error = %v", err)
	}

	// Create a new mailbox
	err = m.CreateMailbox(ctx, "example.com", "testuser", "Archive")
	if err != nil {
		t.Fatalf("CreateMailbox() error = %v", err)
	}

	// Verify it exists
	exists, err := m.MailboxExists(ctx, "example.com", "testuser", "Archive")
	if err != nil {
		t.Fatalf("MailboxExists() error = %v", err)
	}
	if !exists {
		t.Error("Mailbox should exist after creation")
	}

	// Delete the mailbox
	err = m.DeleteMailbox(ctx, "example.com", "testuser", "Archive")
	if err != nil {
		t.Fatalf("DeleteMailbox() error = %v", err)
	}

	// Verify it's gone
	exists, err = m.MailboxExists(ctx, "example.com", "testuser", "Archive")
	if err != nil {
		t.Fatalf("MailboxExists() error = %v", err)
	}
	if exists {
		t.Error("Mailbox should not exist after deletion")
	}
}

func TestMaildir_CreateINBOXError(t *testing.T) {
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

	ctx := context.Background()

	// Should not be able to create INBOX
	err = m.CreateMailbox(ctx, "example.com", "testuser", "INBOX")
	if err == nil {
		t.Error("CreateMailbox(INBOX) should return error")
	}
}

func TestMaildir_RenameMailbox(t *testing.T) {
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

	ctx := context.Background()

	// First create user maildir
	err = m.CreateUserMaildir(ctx, "example.com", "testuser")
	if err != nil {
		t.Fatalf("CreateUserMaildir() error = %v", err)
	}

	// Create a mailbox
	err = m.CreateMailbox(ctx, "example.com", "testuser", "OldName")
	if err != nil {
		t.Fatalf("CreateMailbox() error = %v", err)
	}

	// Rename it
	err = m.RenameMailbox(ctx, "example.com", "testuser", "OldName", "NewName")
	if err != nil {
		t.Fatalf("RenameMailbox() error = %v", err)
	}

	// Old name should not exist
	exists, _ := m.MailboxExists(ctx, "example.com", "testuser", "OldName")
	if exists {
		t.Error("Old mailbox name should not exist")
	}

	// New name should exist
	exists, _ = m.MailboxExists(ctx, "example.com", "testuser", "NewName")
	if !exists {
		t.Error("New mailbox name should exist")
	}
}

func TestMaildir_ListMailboxes(t *testing.T) {
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

	ctx := context.Background()

	// Create user maildir (creates INBOX and default folders)
	err = m.CreateUserMaildir(ctx, "example.com", "testuser")
	if err != nil {
		t.Fatalf("CreateUserMaildir() error = %v", err)
	}

	// Create additional mailbox
	err = m.CreateMailbox(ctx, "example.com", "testuser", "Work")
	if err != nil {
		t.Fatalf("CreateMailbox() error = %v", err)
	}

	mailboxes, err := m.ListMailboxes(ctx, "example.com", "testuser")
	if err != nil {
		t.Fatalf("ListMailboxes() error = %v", err)
	}

	// Should have INBOX, Sent, Drafts, Trash, Junk, Work
	if len(mailboxes) != 6 {
		t.Errorf("Expected 6 mailboxes, got %d: %v", len(mailboxes), mailboxes)
	}

	// INBOX should be first
	if mailboxes[0] != "INBOX" {
		t.Errorf("First mailbox should be INBOX, got %s", mailboxes[0])
	}
}

func TestMaildir_GenerateFilename(t *testing.T) {
	m := &Maildir{
		hostname: "mail.example.com",
	}

	tests := []struct {
		name  string
		flags []string
		check func(string) bool
	}{
		{
			name:  "no flags",
			flags: nil,
			check: func(s string) bool {
				return strings.Contains(s, "mail.example.com:2,")
			},
		},
		{
			name:  "seen flag",
			flags: []string{"\\Seen"},
			check: func(s string) bool {
				return strings.HasSuffix(s, ":2,S")
			},
		},
		{
			name:  "multiple flags sorted",
			flags: []string{"\\Seen", "\\Flagged", "\\Answered"},
			check: func(s string) bool {
				return strings.HasSuffix(s, ":2,FRS")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := m.GenerateFilename(tt.flags)
			if !tt.check(filename) {
				t.Errorf("GenerateFilename() = %v, failed check", filename)
			}
		})
	}

	// Test uniqueness
	filenames := make(map[string]bool)
	for i := 0; i < 100; i++ {
		fn := m.GenerateFilename(nil)
		if filenames[fn] {
			t.Errorf("Duplicate filename generated: %s", fn)
		}
		filenames[fn] = true
	}
}

func TestMaildir_EncodeDecodeFlags(t *testing.T) {
	m := &Maildir{}

	tests := []struct {
		name      string
		imapFlags []string
		wantStr   string
	}{
		{
			name:      "empty flags",
			imapFlags: nil,
			wantStr:   "",
		},
		{
			name:      "seen",
			imapFlags: []string{"\\Seen"},
			wantStr:   "S",
		},
		{
			name:      "answered",
			imapFlags: []string{"\\Answered"},
			wantStr:   "R",
		},
		{
			name:      "multiple flags",
			imapFlags: []string{"\\Seen", "\\Answered", "\\Flagged"},
			wantStr:   "FRS",
		},
		{
			name:      "all flags",
			imapFlags: []string{"\\Draft", "\\Flagged", "$Forwarded", "\\Answered", "\\Seen", "\\Deleted"},
			wantStr:   "DFPRST", // P is for forwarded
		},
		{
			name:      "duplicate flags",
			imapFlags: []string{"\\Seen", "\\Seen", "\\Flagged"},
			wantStr:   "FS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := m.EncodeFlags(tt.imapFlags)
			if encoded != tt.wantStr {
				t.Errorf("EncodeFlags() = %v, want %v", encoded, tt.wantStr)
			}
		})
	}
}

func TestMaildir_DecodeFlags(t *testing.T) {
	m := &Maildir{}

	tests := []struct {
		name     string
		filename string
		want     []string
	}{
		{
			name:     "no flags",
			filename: "1234567890.M123456P12345.mail.example.com:2,",
			want:     nil,
		},
		{
			name:     "seen flag",
			filename: "1234567890.M123456P12345.mail.example.com:2,S",
			want:     []string{"\\Seen"},
		},
		{
			name:     "multiple flags",
			filename: "1234567890.M123456P12345.mail.example.com:2,FRS",
			want:     []string{"\\Flagged", "\\Answered", "\\Seen"},
		},
		{
			name:     "no info section",
			filename: "1234567890.M123456P12345.mail.example.com",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.DecodeFlags(tt.filename)
			if len(got) != len(tt.want) {
				t.Errorf("DecodeFlags() = %v, want %v", got, tt.want)
				return
			}
			for i, f := range got {
				if f != tt.want[i] {
					t.Errorf("DecodeFlags() flag %d = %v, want %v", i, f, tt.want[i])
				}
			}
		})
	}
}

func TestMaildir_UpdateFilenameFlags(t *testing.T) {
	m := &Maildir{}

	tests := []struct {
		name     string
		filename string
		newFlags []string
		want     string
	}{
		{
			name:     "add flags",
			filename: "1234567890.M123456P12345.mail.example.com:2,",
			newFlags: []string{"\\Seen"},
			want:     "1234567890.M123456P12345.mail.example.com:2,S",
		},
		{
			name:     "change flags",
			filename: "1234567890.M123456P12345.mail.example.com:2,S",
			newFlags: []string{"\\Seen", "\\Flagged"},
			want:     "1234567890.M123456P12345.mail.example.com:2,FS",
		},
		{
			name:     "remove flags",
			filename: "1234567890.M123456P12345.mail.example.com:2,FRS",
			newFlags: nil,
			want:     "1234567890.M123456P12345.mail.example.com:2,",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.UpdateFilenameFlags(tt.filename, tt.newFlags)
			if got != tt.want {
				t.Errorf("UpdateFilenameFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaildir_GetSubdir(t *testing.T) {
	m := &Maildir{}

	tests := []struct {
		name  string
		flags []string
		want  string
	}{
		{
			name:  "no flags - new",
			flags: nil,
			want:  DirNew,
		},
		{
			name:  "seen - cur",
			flags: []string{"\\Seen"},
			want:  DirCur,
		},
		{
			name:  "other flags - new",
			flags: []string{"\\Flagged"},
			want:  DirNew,
		},
		{
			name:  "seen with other flags - cur",
			flags: []string{"\\Flagged", "\\Seen"},
			want:  DirCur,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.GetSubdir(tt.flags)
			if got != tt.want {
				t.Errorf("GetSubdir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpecialUseFolder(t *testing.T) {
	tests := []struct {
		specialUse string
		want       string
	}{
		{SpecialUseSent, "Sent"},
		{SpecialUseDrafts, "Drafts"},
		{SpecialUseTrash, "Trash"},
		{SpecialUseJunk, "Junk"},
		{SpecialUseArchive, "Archive"},
		{"\\Unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.specialUse, func(t *testing.T) {
			got := SpecialUseFolder(tt.specialUse)
			if got != tt.want {
				t.Errorf("SpecialUseFolder(%s) = %v, want %v", tt.specialUse, got, tt.want)
			}
		})
	}
}

func TestGetSpecialUse(t *testing.T) {
	tests := []struct {
		mailboxName string
		want        string
	}{
		{"Sent", SpecialUseSent},
		{"sent", SpecialUseSent},
		{"Sent Items", SpecialUseSent},
		{"Drafts", SpecialUseDrafts},
		{"draft", SpecialUseDrafts},
		{"Trash", SpecialUseTrash},
		{"Deleted", SpecialUseTrash},
		{"Junk", SpecialUseJunk},
		{"Spam", SpecialUseJunk},
		{"Archive", SpecialUseArchive},
		{"INBOX", SpecialUseInbox},
		{"Custom", ""},
	}

	for _, tt := range tests {
		t.Run(tt.mailboxName, func(t *testing.T) {
			got := GetSpecialUse(tt.mailboxName)
			if got != tt.want {
				t.Errorf("GetSpecialUse(%s) = %v, want %v", tt.mailboxName, got, tt.want)
			}
		})
	}
}
