package api

import (
	"database/sql"
	_ "embed"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/dkim"
)

//go:embed openapi.yaml
var openAPISpec []byte

// Health handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Version: "1.0.0",
		Uptime:  time.Since(s.startTime).String(),
		Services: map[string]string{
			"database": "ok",
			"smtp":     "ok",
			"imap":     "ok",
		},
	})
}

func (s *Server) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	// Detailed health check for admins
	services := map[string]string{
		"database": "ok",
		"smtp":     "ok",
		"imap":     "ok",
		"api":      "ok",
	}

	// Check database
	if err := s.db.PingContext(r.Context()); err != nil {
		services["database"] = "error: " + err.Error()
	}

	respondJSON(w, http.StatusOK, HealthResponse{
		Status:   "ok",
		Version:  "1.0.0",
		Uptime:   time.Since(s.startTime).String(),
		Services: services,
	})
}

// OpenAPI spec handler

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(openAPISpec)
}

// Auth handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement actual user lookup and password verification
	// For now, return a placeholder response
	// In production, this would:
	// 1. Look up user by email
	// 2. Verify password hash
	// 3. Generate JWT token
	// 4. Update last_login timestamp

	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "authentication not yet implemented")
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// Validate the existing token
	claims, err := s.jwtAuth.ValidateToken(req.Token)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired token")
		return
	}

	// Generate a new token
	token, expiresAt, err := s.jwtAuth.GenerateToken(claims.UserID, claims.Email, claims.DomainID, claims.IsAdmin)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "TOKEN_ERROR", "failed to generate token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	respondJSON(w, http.StatusOK, UserResponse{
		ID:       claims.UserID,
		Email:    claims.Email,
		DomainID: claims.DomainID,
		IsAdmin:  claims.IsAdmin,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// In a stateless JWT system, logout is handled client-side
	// Could implement token blacklisting if needed
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

// Domain handlers

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT id, name, enabled, dkim_selector, max_mailbox_size, max_message_size, created_at, updated_at
		FROM domains
		ORDER BY name
	`

	rows, err := s.db.QueryContext(r.Context(), query)
	if err != nil {
		s.logger.Error("failed to list domains", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to list domains")
		return
	}
	defer rows.Close()

	var domains []DomainResponse
	for rows.Next() {
		var d DomainResponse
		var dkimSelector sql.NullString
		if err := rows.Scan(&d.ID, &d.Name, &d.Enabled, &dkimSelector, &d.MaxMailboxSize, &d.MaxMessageSize, &d.CreatedAt, &d.UpdatedAt); err != nil {
			s.logger.Error("failed to scan domain", "error", err)
			continue
		}
		if dkimSelector.Valid {
			d.DKIMSelector = dkimSelector.String
		}
		domains = append(domains, d)
	}

	if domains == nil {
		domains = []DomainResponse{}
	}
	respondJSON(w, http.StatusOK, domains)
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req CreateDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// Normalize domain name
	domainName := strings.ToLower(strings.TrimSpace(req.Name))

	// Check if domain already exists
	var exists bool
	err := s.db.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM domains WHERE LOWER(name) = $1)", domainName).Scan(&exists)
	if err != nil {
		s.logger.Error("failed to check domain existence", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to check domain")
		return
	}
	if exists {
		respondError(w, http.StatusConflict, "DOMAIN_EXISTS", "domain already exists")
		return
	}

	// Generate DKIM key if manager is configured
	var dkimSelector string
	if s.dkimManager != nil {
		keyInfo, err := s.dkimManager.GenerateKey(domainName)
		if err != nil {
			s.logger.Error("failed to generate DKIM key", "domain", domainName, "error", err)
			respondError(w, http.StatusInternalServerError, "DKIM_ERROR", "failed to generate DKIM key")
			return
		}
		dkimSelector = keyInfo.Selector
		s.logger.Info("DKIM key generated for domain", "domain", domainName, "selector", dkimSelector)
	}

	// Set defaults
	maxMailboxSize := req.MaxMailboxSize
	if maxMailboxSize == 0 {
		maxMailboxSize = 1073741824 // 1GB default
	}
	maxMessageSize := req.MaxMessageSize
	if maxMessageSize == 0 {
		maxMessageSize = 26214400 // 25MB default
	}

	// Insert domain
	domainID := uuid.New()
	now := time.Now()

	query := `
		INSERT INTO domains (id, name, enabled, dkim_selector, max_mailbox_size, max_message_size, created_at, updated_at)
		VALUES ($1, $2, true, $3, $4, $5, $6, $7)
	`
	_, err = s.db.ExecContext(r.Context(), query, domainID, domainName, dkimSelector, maxMailboxSize, maxMessageSize, now, now)
	if err != nil {
		s.logger.Error("failed to create domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to create domain")
		return
	}

	resp := DomainResponse{
		ID:             domainID,
		Name:           domainName,
		Enabled:        true,
		DKIMSelector:   dkimSelector,
		MaxMailboxSize: maxMailboxSize,
		MaxMessageSize: maxMessageSize,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.logger.Info("domain created", "id", domainID, "name", domainName)
	respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if _, err := uuid.Parse(domainID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain ID")
		return
	}

	query := `
		SELECT id, name, enabled, dkim_selector, max_mailbox_size, max_message_size, created_at, updated_at
		FROM domains
		WHERE id = $1
	`

	var d DomainResponse
	var dkimSelector sql.NullString
	err := s.db.QueryRowContext(r.Context(), query, domainID).Scan(
		&d.ID, &d.Name, &d.Enabled, &dkimSelector, &d.MaxMailboxSize, &d.MaxMessageSize, &d.CreatedAt, &d.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		s.logger.Error("failed to get domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to get domain")
		return
	}

	if dkimSelector.Valid {
		d.DKIMSelector = dkimSelector.String
	}

	respondJSON(w, http.StatusOK, d)
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if _, err := uuid.Parse(domainID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain ID")
		return
	}

	var req UpdateDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// Build dynamic update query
	var updates []string
	var args []interface{}
	argNum := 1

	if req.Enabled != nil {
		updates = append(updates, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *req.Enabled)
		argNum++
	}
	if req.MaxMailboxSize != nil {
		updates = append(updates, fmt.Sprintf("max_mailbox_size = $%d", argNum))
		args = append(args, *req.MaxMailboxSize)
		argNum++
	}
	if req.MaxMessageSize != nil {
		updates = append(updates, fmt.Sprintf("max_message_size = $%d", argNum))
		args = append(args, *req.MaxMessageSize)
		argNum++
	}

	if len(updates) == 0 {
		respondError(w, http.StatusBadRequest, "NO_UPDATES", "no fields to update")
		return
	}

	updates = append(updates, fmt.Sprintf("updated_at = $%d", argNum))
	args = append(args, time.Now())
	argNum++

	args = append(args, domainID)
	query := fmt.Sprintf("UPDATE domains SET %s WHERE id = $%d", strings.Join(updates, ", "), argNum)

	result, err := s.db.ExecContext(r.Context(), query, args...)
	if err != nil {
		s.logger.Error("failed to update domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to update domain")
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}

	// Return updated domain
	s.handleGetDomain(w, r)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if _, err := uuid.Parse(domainID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain ID")
		return
	}

	// Get domain name for DKIM key deletion
	var domainName string
	err := s.db.QueryRowContext(r.Context(), "SELECT name FROM domains WHERE id = $1", domainID).Scan(&domainName)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		s.logger.Error("failed to get domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to get domain")
		return
	}

	// Delete domain from database
	_, err = s.db.ExecContext(r.Context(), "DELETE FROM domains WHERE id = $1", domainID)
	if err != nil {
		s.logger.Error("failed to delete domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to delete domain")
		return
	}

	// Delete DKIM key
	if s.dkimManager != nil {
		if err := s.dkimManager.DeleteKey(domainName); err != nil {
			s.logger.Warn("failed to delete DKIM key", "domain", domainName, "error", err)
		}
	}

	s.logger.Info("domain deleted", "id", domainID, "name", domainName)
	respondJSON(w, http.StatusOK, map[string]string{"message": "domain deleted"})
}

func (s *Server) handleGetDNSRecords(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if _, err := uuid.Parse(domainID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain ID")
		return
	}

	// Get domain name
	var domainName string
	err := s.db.QueryRowContext(r.Context(), "SELECT name FROM domains WHERE id = $1", domainID).Scan(&domainName)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		s.logger.Error("failed to get domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to get domain")
		return
	}

	hostname := s.hostname
	if hostname == "" {
		hostname = "mail." + domainName
	}

	records := []DNSRecordResponse{
		// MX record
		{
			Type:     "MX",
			Name:     domainName,
			Value:    hostname,
			Priority: 10,
			TTL:      3600,
		},
		// SPF record
		{
			Type:  "TXT",
			Name:  domainName,
			Value: fmt.Sprintf("v=spf1 mx a:%s ~all", hostname),
			TTL:   3600,
		},
	}

	// Add DKIM record if key exists
	if s.dkimManager != nil {
		dnsName, dnsRecord, err := s.dkimManager.GetDNSRecord(domainName)
		if err == nil {
			records = append(records, DNSRecordResponse{
				Type:  "TXT",
				Name:  dnsName,
				Value: dkim.FormatDNSRecordForDisplay(dnsRecord),
				TTL:   3600,
			})
		}
	}

	// DMARC record
	records = append(records, DNSRecordResponse{
		Type:  "TXT",
		Name:  "_dmarc." + domainName,
		Value: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:postmaster@%s", domainName),
		TTL:   3600,
	})

	respondJSON(w, http.StatusOK, records)
}

func (s *Server) handleRotateDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if _, err := uuid.Parse(domainID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain ID")
		return
	}

	if s.dkimManager == nil {
		respondError(w, http.StatusServiceUnavailable, "DKIM_DISABLED", "DKIM is not configured")
		return
	}

	// Get domain name
	var domainName string
	err := s.db.QueryRowContext(r.Context(), "SELECT name FROM domains WHERE id = $1", domainID).Scan(&domainName)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		s.logger.Error("failed to get domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to get domain")
		return
	}

	// Rotate DKIM key
	keyInfo, err := s.dkimManager.RotateKey(domainName)
	if err != nil {
		s.logger.Error("failed to rotate DKIM key", "domain", domainName, "error", err)
		respondError(w, http.StatusInternalServerError, "DKIM_ERROR", "failed to rotate DKIM key")
		return
	}

	s.logger.Info("DKIM key rotated", "domain", domainName, "selector", keyInfo.Selector)

	// Return the new DNS record
	respondJSON(w, http.StatusOK, map[string]any{
		"message":    "DKIM key rotated successfully",
		"selector":   keyInfo.Selector,
		"dns_name":   keyInfo.DNSName,
		"dns_record": dkim.FormatDNSRecordForDisplay(keyInfo.DNSRecord),
	})
}

// User handlers

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	// TODO: Implement user listing
	respondJSONWithMeta(w, http.StatusOK, []UserResponse{}, &Meta{
		Page:       page,
		PerPage:    perPage,
		Total:      0,
		TotalPages: 0,
	})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement user creation
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "user creation not yet implemented")
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if _, err := uuid.Parse(userID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	// TODO: Implement user lookup
	respondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if _, err := uuid.Parse(userID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	var req UpdateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// TODO: Implement user update
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "user update not yet implemented")
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if _, err := uuid.Parse(userID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	// TODO: Implement user deletion
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "user deletion not yet implemented")
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if _, err := uuid.Parse(userID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	var req ChangePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement password change
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "password change not yet implemented")
}

func (s *Server) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if _, err := uuid.Parse(userID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	// TODO: Implement quota lookup
	respondJSON(w, http.StatusOK, QuotaResponse{
		QuotaBytes:   0,
		UsedBytes:    0,
		UsedPercent:  0,
		MessageCount: 0,
	})
}

// Alias handlers

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, []AliasResponse{})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	var req CreateAliasRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement alias creation
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "alias creation not yet implemented")
}

func (s *Server) handleGetAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")
	if _, err := uuid.Parse(aliasID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid alias ID")
		return
	}

	respondError(w, http.StatusNotFound, "NOT_FOUND", "alias not found")
}

func (s *Server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")
	if _, err := uuid.Parse(aliasID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid alias ID")
		return
	}

	// TODO: Implement alias update
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "alias update not yet implemented")
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")
	if _, err := uuid.Parse(aliasID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid alias ID")
		return
	}

	// TODO: Implement alias deletion
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "alias deletion not yet implemented")
}

// Mailbox handlers

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, []MailboxResponse{})
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	var req CreateMailboxRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement mailbox creation
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "mailbox creation not yet implemented")
}

func (s *Server) handleGetMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if _, err := uuid.Parse(mailboxID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid mailbox ID")
		return
	}

	respondError(w, http.StatusNotFound, "NOT_FOUND", "mailbox not found")
}

func (s *Server) handleUpdateMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if _, err := uuid.Parse(mailboxID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid mailbox ID")
		return
	}

	// TODO: Implement mailbox update
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "mailbox update not yet implemented")
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if _, err := uuid.Parse(mailboxID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid mailbox ID")
		return
	}

	// TODO: Implement mailbox deletion
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "mailbox deletion not yet implemented")
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if _, err := uuid.Parse(mailboxID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid mailbox ID")
		return
	}

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	respondJSONWithMeta(w, http.StatusOK, []MessageResponse{}, &Meta{
		Page:       page,
		PerPage:    perPage,
		Total:      0,
		TotalPages: 0,
	})
}

// Message handlers

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if _, err := uuid.Parse(messageID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid message ID")
		return
	}

	respondError(w, http.StatusNotFound, "NOT_FOUND", "message not found")
}

func (s *Server) handleGetRawMessage(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if _, err := uuid.Parse(messageID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid message ID")
		return
	}

	// TODO: Return raw message content
	respondError(w, http.StatusNotFound, "NOT_FOUND", "message not found")
}

func (s *Server) handleUpdateFlags(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if _, err := uuid.Parse(messageID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid message ID")
		return
	}

	var req UpdateFlagsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// TODO: Implement flag update
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "flag update not yet implemented")
}

func (s *Server) handleMoveMessage(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if _, err := uuid.Parse(messageID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid message ID")
		return
	}

	var req MoveMessageRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := s.validator.Struct(req); err != nil {
		respondValidationError(w, err)
		return
	}

	// TODO: Implement message move
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "message move not yet implemented")
}

func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if _, err := uuid.Parse(messageID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid message ID")
		return
	}

	// TODO: Implement message deletion
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "message deletion not yet implemented")
}

// Queue handlers

func (s *Server) handleListQueue(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, []QueueItemResponse{})
}

func (s *Server) handleGetQueueItem(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	if _, err := uuid.Parse(queueID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid queue ID")
		return
	}

	respondError(w, http.StatusNotFound, "NOT_FOUND", "queue item not found")
}

func (s *Server) handleCancelQueue(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	if _, err := uuid.Parse(queueID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid queue ID")
		return
	}

	// TODO: Implement queue cancellation
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "queue cancellation not yet implemented")
}

func (s *Server) handleRetryQueue(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	if _, err := uuid.Parse(queueID); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid queue ID")
		return
	}

	// TODO: Implement queue retry
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "queue retry not yet implemented")
}

// Stats handlers

func (s *Server) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, StatsOverviewResponse{
		Domains:       0,
		Users:         0,
		Messages:      0,
		StorageUsed:   0,
		QueueSize:     0,
		MessagesToday: 0,
		MessagesHour:  0,
	})
}

func (s *Server) handleStatsMessages(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"total":    0,
		"received": 0,
		"sent":     0,
		"spam":     0,
		"virus":    0,
	})
}

func (s *Server) handleStatsQueue(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"pending":   0,
		"deferred":  0,
		"failed":    0,
		"delivered": 0,
	})
}

// Admin handlers

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement configuration reload
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "configuration reloaded",
	})
}
