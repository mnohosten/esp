package imap

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/mnohosten/esp/internal/mailbox"
)

// Session implements imapserver.Session for a single connection.
type Session struct {
	backend    *Backend
	conn       net.Conn
	remoteAddr string
	logger     *slog.Logger

	// Authenticated user
	user *User

	// Selected mailbox
	selectedMailbox  *mailbox.Mailbox
	selectedReadOnly bool
}

// Ensure Session implements the required interfaces
var _ imapserver.Session = (*Session)(nil)
var _ imapserver.SessionMove = (*Session)(nil)
var _ imapserver.SessionNamespace = (*Session)(nil)

// Close closes the session.
func (s *Session) Close() error {
	s.logger.Debug("session closed")
	return nil
}

// Not authenticated state handlers

// Login handles the LOGIN command.
func (s *Session) Login(username, password string) error {
	ctx := context.Background()

	user, err := s.backend.Authenticate(ctx, username, password)
	if err != nil {
		s.logger.Info("login failed", "username", username, "error", err)
		return imapserver.ErrAuthFailed
	}

	s.user = user
	s.logger = s.logger.With("user_id", user.ID, "email", user.Email)
	s.logger.Info("login successful")

	return nil
}

// Authenticated state handlers

// ensureAuthenticated returns an error if the session is not authenticated.
func (s *Session) ensureAuthenticated() error {
	if s.user == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Not authenticated",
		}
	}
	return nil
}

// ensureSelected returns an error if no mailbox is selected.
func (s *Session) ensureSelected() error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}
	if s.selectedMailbox == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "No mailbox selected",
		}
	}
	return nil
}

// Select selects a mailbox.
func (s *Session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if err := s.ensureAuthenticated(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	// Get mailbox by name
	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, name)
	if err != nil {
		s.logger.Debug("mailbox not found", "name", name)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	// Update mailbox counts
	s.backend.mailboxMgr.UpdateCounts(ctx, mb.ID)

	// Refresh mailbox data
	mb, _ = s.backend.mailboxMgr.Get(ctx, mb.ID)

	s.selectedMailbox = mb
	s.selectedReadOnly = options != nil && options.ReadOnly

	s.logger.Debug("mailbox selected",
		"name", name,
		"readonly", s.selectedReadOnly,
		"message_count", mb.MessageCount,
		"unread_count", mb.UnreadCount,
	)

	// Build select response
	data := &imap.SelectData{
		Flags:          []imap.Flag{imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagSeen, imap.FlagDraft},
		PermanentFlags: []imap.Flag{imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagSeen, imap.FlagDraft, imap.FlagWildcard},
		NumMessages:    uint32(mb.MessageCount),
		UIDValidity:    mb.UIDValidity,
		UIDNext:        imap.UID(mb.UIDNext),
	}

	return data, nil
}

// Unselect unselects the current mailbox.
func (s *Session) Unselect() error {
	s.selectedMailbox = nil
	s.selectedReadOnly = false
	return nil
}

// Create creates a new mailbox.
func (s *Session) Create(name string, options *imap.CreateOptions) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	// Check if mailbox already exists
	exists, _ := s.backend.mailboxMgr.Exists(ctx, s.user.ID, name)
	if exists {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "Mailbox already exists",
		}
	}

	// Determine special use if applicable
	specialUse := ""
	if options != nil && len(options.SpecialUse) > 0 {
		specialUse = string(options.SpecialUse[0])
	}

	_, err := s.backend.mailboxMgr.Create(ctx, s.user.ID, name, specialUse)
	if err != nil {
		s.logger.Error("failed to create mailbox", "name", name, "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Failed to create mailbox",
		}
	}

	s.logger.Info("mailbox created", "name", name)
	return nil
}

// Delete deletes a mailbox.
func (s *Session) Delete(name string) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, name)
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	// Cannot delete INBOX
	if strings.EqualFold(name, "INBOX") {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot delete INBOX",
		}
	}

	if err := s.backend.mailboxMgr.Delete(ctx, mb.ID); err != nil {
		s.logger.Error("failed to delete mailbox", "name", name, "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Failed to delete mailbox",
		}
	}

	s.logger.Info("mailbox deleted", "name", name)
	return nil
}

// Rename renames a mailbox.
func (s *Session) Rename(oldName, newName string, options *imap.RenameOptions) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, oldName)
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	// Check if destination exists
	exists, _ := s.backend.mailboxMgr.Exists(ctx, s.user.ID, newName)
	if exists {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "Destination mailbox already exists",
		}
	}

	if err := s.backend.mailboxMgr.Rename(ctx, mb.ID, newName); err != nil {
		s.logger.Error("failed to rename mailbox", "old", oldName, "new", newName, "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Failed to rename mailbox",
		}
	}

	s.logger.Info("mailbox renamed", "old", oldName, "new", newName)
	return nil
}

// Subscribe subscribes to a mailbox.
func (s *Session) Subscribe(name string) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, name)
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	return s.backend.mailboxMgr.Subscribe(ctx, mb.ID)
}

// Unsubscribe unsubscribes from a mailbox.
func (s *Session) Unsubscribe(name string) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, name)
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	return s.backend.mailboxMgr.Unsubscribe(ctx, mb.ID)
}

// List lists mailboxes.
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if err := s.ensureAuthenticated(); err != nil {
		return err
	}

	ctx := context.Background()

	// Get all mailboxes for the user
	mailboxes, err := s.backend.mailboxMgr.List(ctx, s.user.ID)
	if err != nil {
		return err
	}

	// Filter by subscription if LSUB
	if options != nil && options.SelectSubscribed {
		var subscribed []*mailbox.Mailbox
		for _, mb := range mailboxes {
			if mb.Subscribed {
				subscribed = append(subscribed, mb)
			}
		}
		mailboxes = subscribed
	}

	// Write each mailbox
	for _, mb := range mailboxes {
		// Check if mailbox matches any pattern
		matched := false
		for _, pattern := range patterns {
			if imapserver.MatchList(mb.Name, '/', ref, pattern) {
				matched = true
				break
			}
		}
		if !matched && len(patterns) > 0 {
			continue
		}

		data := &imap.ListData{
			Mailbox: mb.Name,
			Delim:   '/',
		}

		// Add special-use attributes
		if mb.SpecialUse != "" {
			switch mb.SpecialUse {
			case mailbox.SpecialUseSent:
				data.Attrs = append(data.Attrs, imap.MailboxAttrSent)
			case mailbox.SpecialUseDrafts:
				data.Attrs = append(data.Attrs, imap.MailboxAttrDrafts)
			case mailbox.SpecialUseTrash:
				data.Attrs = append(data.Attrs, imap.MailboxAttrTrash)
			case mailbox.SpecialUseJunk:
				data.Attrs = append(data.Attrs, imap.MailboxAttrJunk)
			case mailbox.SpecialUseArchive:
				data.Attrs = append(data.Attrs, imap.MailboxAttrArchive)
			}
		}

		// Add STATUS data if requested
		if options != nil && options.ReturnStatus != nil {
			data.Status = &imap.StatusData{
				Mailbox:     mb.Name,
				NumMessages: ptrUint32(uint32(mb.MessageCount)),
				NumUnseen:   ptrUint32(uint32(mb.UnreadCount)),
				UIDValidity: mb.UIDValidity,
				UIDNext:     imap.UID(mb.UIDNext),
			}
		}

		if err := w.WriteList(data); err != nil {
			return err
		}
	}

	return nil
}

// Status returns mailbox status.
func (s *Session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if err := s.ensureAuthenticated(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, name)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "Mailbox does not exist",
		}
	}

	// Update counts
	s.backend.mailboxMgr.UpdateCounts(ctx, mb.ID)
	mb, _ = s.backend.mailboxMgr.Get(ctx, mb.ID)

	data := &imap.StatusData{
		Mailbox: mb.Name,
	}

	// Only include requested items
	if options != nil {
		if options.NumMessages {
			data.NumMessages = ptrUint32(uint32(mb.MessageCount))
		}
		if options.NumUnseen {
			data.NumUnseen = ptrUint32(uint32(mb.UnreadCount))
		}
		if options.UIDNext {
			data.UIDNext = imap.UID(mb.UIDNext)
		}
		if options.UIDValidity {
			data.UIDValidity = mb.UIDValidity
		}
	}

	return data, nil
}

// Append appends a message to a mailbox.
func (s *Session) Append(mailboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if err := s.ensureAuthenticated(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	mb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, mailboxName)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "Mailbox does not exist",
		}
	}

	// Read message content
	content := make([]byte, r.Size())
	if _, err := r.Read(content); err != nil {
		return nil, err
	}

	// Convert flags
	var flags []string
	if options != nil {
		for _, f := range options.Flags {
			flags = append(flags, string(f))
		}
	}

	// Check quota
	if err := s.backend.quotaMgr.CheckQuota(ctx, s.user.ID, int64(len(content))); err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeOverQuota,
			Text: "Quota exceeded",
		}
	}

	// Store message
	msg, err := s.backend.messageStore.StoreMessage(ctx, mb.ID, content, flags)
	if err != nil {
		s.logger.Error("failed to append message", "mailbox", mailboxName, "error", err)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Failed to append message",
		}
	}

	// Update quota
	s.backend.quotaMgr.UpdateUsedBytes(ctx, s.user.ID, int64(len(content)))

	s.logger.Debug("message appended",
		"mailbox", mailboxName,
		"uid", msg.UID,
		"size", len(content),
	)

	return &imap.AppendData{
		UIDValidity: mb.UIDValidity,
		UID:         imap.UID(msg.UID),
	}, nil
}

// Poll checks for mailbox updates (used for NOOP).
func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// For now, just return without updates
	// TODO: Implement real polling for updates
	return nil
}

// Idle handles the IDLE command.
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if err := s.ensureSelected(); err != nil {
		return err
	}

	// Wait for stop signal or timeout
	idleTimeout := 30 * time.Minute

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	select {
	case <-stop:
		return nil
	case <-timer.C:
		return nil
	}
}

// Selected state handlers

// Expunge permanently removes messages marked for deletion.
func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if err := s.ensureSelected(); err != nil {
		return err
	}

	if s.selectedReadOnly {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Mailbox is read-only",
		}
	}

	ctx := context.Background()

	// Get all messages with \Deleted flag
	criteria := &mailbox.SearchCriteria{Deleted: true}
	deletedUIDs, err := s.backend.searcher.Search(ctx, s.selectedMailbox.ID, criteria)
	if err != nil {
		return err
	}

	// Filter by UID set if specified
	if uids != nil {
		var filtered []uint32
		for _, uid := range deletedUIDs {
			if uids.Contains(imap.UID(uid)) {
				filtered = append(filtered, uid)
			}
		}
		deletedUIDs = filtered
	}

	// Delete each message
	for _, uid := range deletedUIDs {
		if err := s.backend.messageStore.DeleteMessage(ctx, s.selectedMailbox.ID, uid); err != nil {
			s.logger.Warn("failed to expunge message", "uid", uid, "error", err)
			continue
		}

		// Write expunge notification
		if err := w.WriteExpunge(uint32(uid)); err != nil {
			return err
		}
	}

	return nil
}

// Search searches for messages.
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if err := s.ensureSelected(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	// Convert IMAP criteria to our internal format
	internalCriteria := convertSearchCriteria(criteria)

	uids, err := s.backend.searcher.Search(ctx, s.selectedMailbox.ID, internalCriteria)
	if err != nil {
		return nil, err
	}

	data := &imap.SearchData{}
	if kind == imapserver.NumKindUID {
		var uidSlice []imap.UID
		for _, uid := range uids {
			uidSlice = append(uidSlice, imap.UID(uid))
		}
		data.All = imap.UIDSetNum(uidSlice...)
	} else {
		// For sequence numbers, we need to convert
		// For now, just use UIDs as sequence numbers (simplified)
		var seqSet imap.SeqSet
		for _, uid := range uids {
			seqSet.AddNum(uid)
		}
		data.All = seqSet
	}

	return data, nil
}

// Fetch retrieves message data.
func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if err := s.ensureSelected(); err != nil {
		return err
	}

	ctx := context.Background()

	// Get messages in the set
	messages, err := s.backend.messageStore.GetAllMessages(ctx, s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	for _, msg := range messages {
		// Check if message is in the requested set
		if !numSetContains(numSet, msg.UID) {
			continue
		}

		// Create fetch response writer
		respWriter := w.CreateMessage(msg.UID)

		// Write requested data items
		if options.UID {
			respWriter.WriteUID(imap.UID(msg.UID))
		}

		if options.Flags {
			var flags []imap.Flag
			for _, f := range msg.Flags {
				flags = append(flags, imap.Flag(f))
			}
			respWriter.WriteFlags(flags)
		}

		if options.InternalDate {
			respWriter.WriteInternalDate(msg.InternalDate)
		}

		if options.RFC822Size {
			respWriter.WriteRFC822Size(msg.Size)
		}

		if options.Envelope {
			env := buildEnvelope(msg)
			respWriter.WriteEnvelope(env)
		}

		// Handle body sections
		for _, section := range options.BodySection {
			content, err := s.backend.messageStore.GetMessageContent(ctx, s.selectedMailbox.ID, msg.UID)
			if err != nil {
				continue
			}

			// For now, return full content
			// TODO: Implement proper section handling
			sectionWriter := respWriter.WriteBodySection(section, int64(len(content)))
			sectionWriter.Write(content)
			sectionWriter.Close()
		}

		if err := respWriter.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Store modifies message flags.
func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if err := s.ensureSelected(); err != nil {
		return err
	}

	if s.selectedReadOnly {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Mailbox is read-only",
		}
	}

	ctx := context.Background()

	// Get messages in the set
	messages, err := s.backend.messageStore.GetAllMessages(ctx, s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	for _, msg := range messages {
		if !numSetContains(numSet, msg.UID) {
			continue
		}

		// Convert flags
		var newFlags []string
		for _, f := range flags.Flags {
			newFlags = append(newFlags, string(f))
		}

		// Apply flag operation
		switch flags.Op {
		case imap.StoreFlagsSet:
			err = s.backend.messageStore.SetFlags(ctx, s.selectedMailbox.ID, msg.UID, newFlags)
		case imap.StoreFlagsAdd:
			err = s.backend.messageStore.AddFlags(ctx, s.selectedMailbox.ID, msg.UID, newFlags)
		case imap.StoreFlagsDel:
			err = s.backend.messageStore.RemoveFlags(ctx, s.selectedMailbox.ID, msg.UID, newFlags)
		}

		if err != nil {
			s.logger.Warn("failed to update flags", "uid", msg.UID, "error", err)
			continue
		}

		// Write response (always, as go-imap v2 doesn't have Silent option here)
		if options != nil {
			// Get updated message
			updatedMsg, _ := s.backend.messageStore.GetMessage(ctx, s.selectedMailbox.ID, msg.UID)
			if updatedMsg != nil {
				respWriter := w.CreateMessage(msg.UID)
				var respFlags []imap.Flag
				for _, f := range updatedMsg.Flags {
					respFlags = append(respFlags, imap.Flag(f))
				}
				respWriter.WriteFlags(respFlags)
				respWriter.Close()
			}
		}
	}

	return nil
}

// Copy copies messages to another mailbox.
func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if err := s.ensureSelected(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	// Get destination mailbox
	destMb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, dest)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "Destination mailbox does not exist",
		}
	}

	// Get messages in the set
	messages, err := s.backend.messageStore.GetAllMessages(ctx, s.selectedMailbox.ID)
	if err != nil {
		return nil, err
	}

	var sourceUIDs, destUIDs []imap.UID

	for _, msg := range messages {
		if !numSetContains(numSet, msg.UID) {
			continue
		}

		newUID, err := s.backend.messageStore.CopyMessage(ctx, s.selectedMailbox.ID, destMb.ID, msg.UID)
		if err != nil {
			s.logger.Warn("failed to copy message", "uid", msg.UID, "error", err)
			continue
		}

		sourceUIDs = append(sourceUIDs, imap.UID(msg.UID))
		destUIDs = append(destUIDs, imap.UID(newUID))
	}

	return &imap.CopyData{
		UIDValidity: destMb.UIDValidity,
		SourceUIDs:  imap.UIDSetNum(sourceUIDs...),
		DestUIDs:    imap.UIDSetNum(destUIDs...),
	}, nil
}

// Move moves messages to another mailbox (MOVE extension).
func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	if err := s.ensureSelected(); err != nil {
		return err
	}

	if s.selectedReadOnly {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Mailbox is read-only",
		}
	}

	ctx := context.Background()

	// Get destination mailbox
	destMb, err := s.backend.mailboxMgr.GetByName(ctx, s.user.ID, dest)
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "Destination mailbox does not exist",
		}
	}

	// Get messages in the set
	messages, err := s.backend.messageStore.GetAllMessages(ctx, s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	var sourceUIDs, destUIDs []imap.UID
	var seqNums []uint32

	for _, msg := range messages {
		if !numSetContains(numSet, msg.UID) {
			continue
		}

		// Copy message to destination
		newUID, err := s.backend.messageStore.CopyMessage(ctx, s.selectedMailbox.ID, destMb.ID, msg.UID)
		if err != nil {
			s.logger.Warn("failed to copy message during move", "uid", msg.UID, "error", err)
			continue
		}

		sourceUIDs = append(sourceUIDs, imap.UID(msg.UID))
		destUIDs = append(destUIDs, imap.UID(newUID))
		seqNums = append(seqNums, msg.UID) // Using UID as seq num for simplicity
	}

	// Write copy data first
	if err := w.WriteCopyData(&imap.CopyData{
		UIDValidity: destMb.UIDValidity,
		SourceUIDs:  imap.UIDSetNum(sourceUIDs...),
		DestUIDs:    imap.UIDSetNum(destUIDs...),
	}); err != nil {
		return err
	}

	// Delete original messages and send expunge notifications
	for i, uid := range sourceUIDs {
		if err := s.backend.messageStore.DeleteMessage(ctx, s.selectedMailbox.ID, uint32(uid)); err != nil {
			s.logger.Warn("failed to delete source message during move", "uid", uid, "error", err)
			continue
		}

		if err := w.WriteExpunge(seqNums[i]); err != nil {
			return err
		}
	}

	s.logger.Debug("messages moved",
		"count", len(sourceUIDs),
		"destination", dest,
	)

	return nil
}

// Namespace returns namespace information (NAMESPACE extension).
func (s *Session) Namespace() (*imap.NamespaceData, error) {
	if err := s.ensureAuthenticated(); err != nil {
		return nil, err
	}

	// Return standard personal namespace with "/" delimiter
	return &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{
			{
				Prefix: "",
				Delim:  '/',
			},
		},
		// Other and Shared namespaces are nil (not supported)
	}, nil
}

// Helper functions

func ptrUint32(v uint32) *uint32 {
	return &v
}

func numSetContains(numSet imap.NumSet, uid uint32) bool {
	// NumSet can be either sequence numbers or UIDs
	// For simplicity, check if it contains the UID
	switch s := numSet.(type) {
	case imap.SeqSet:
		return s.Contains(uid)
	case imap.UIDSet:
		return s.Contains(imap.UID(uid))
	}
	return false
}

func convertSearchCriteria(c *imap.SearchCriteria) *mailbox.SearchCriteria {
	if c == nil {
		return &mailbox.SearchCriteria{All: true}
	}

	result := &mailbox.SearchCriteria{}

	// Flag criteria
	for _, f := range c.Flag {
		switch f {
		case imap.FlagAnswered:
			result.Answered = true
		case imap.FlagDeleted:
			result.Deleted = true
		case imap.FlagDraft:
			result.Draft = true
		case imap.FlagFlagged:
			result.Flagged = true
		case imap.FlagSeen:
			result.Seen = true
		}
	}

	for _, f := range c.NotFlag {
		switch f {
		case imap.FlagAnswered:
			result.Unanswered = true
		case imap.FlagDeleted:
			result.Undeleted = true
		case imap.FlagDraft:
			result.Undraft = true
		case imap.FlagFlagged:
			result.Unflagged = true
		case imap.FlagSeen:
			result.Unseen = true
		}
	}

	// Date criteria
	if !c.Since.IsZero() {
		since := c.Since
		result.Since = &since
	}
	if !c.Before.IsZero() {
		before := c.Before
		result.Before = &before
	}

	// Size criteria
	if c.Larger > 0 {
		result.Larger = c.Larger
	}
	if c.Smaller > 0 {
		result.Smaller = c.Smaller
	}

	// Header criteria
	for _, h := range c.Header {
		switch strings.ToLower(h.Key) {
		case "from":
			result.From = h.Value
		case "to":
			result.To = h.Value
		case "cc":
			result.Cc = h.Value
		case "subject":
			result.Subject = h.Value
		default:
			if result.Header == nil {
				result.Header = make(map[string]string)
			}
			result.Header[h.Key] = h.Value
		}
	}

	// Body/text search
	for _, t := range c.Body {
		result.Body = t
	}
	for _, t := range c.Text {
		result.Text = t
	}

	return result
}

func buildEnvelope(msg *mailbox.Message) *imap.Envelope {
	env := &imap.Envelope{
		Subject:   msg.Subject,
		MessageID: msg.MessageID,
	}

	// InReplyTo is []string in go-imap v2
	if msg.InReplyTo != "" {
		env.InReplyTo = []string{msg.InReplyTo}
	}

	if msg.Date != nil {
		env.Date = *msg.Date
	}

	if msg.FromAddress != "" {
		env.From = []imap.Address{parseAddress(msg.FromAddress)}
	}

	for _, addr := range msg.ToAddresses {
		env.To = append(env.To, parseAddress(addr))
	}

	for _, addr := range msg.CcAddresses {
		env.Cc = append(env.Cc, parseAddress(addr))
	}

	return env
}

// parseAddress parses an email address string into imap.Address
func parseAddress(addr string) imap.Address {
	// Simple parsing - split on @ for mailbox and host
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return imap.Address{
			Mailbox: parts[0],
			Host:    parts[1],
		}
	}
	// If no @, put everything in mailbox
	return imap.Address{
		Mailbox: addr,
	}
}
