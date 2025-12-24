package mailbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/database"
)

// ErrQuotaExceeded is returned when a user's quota would be exceeded
var ErrQuotaExceeded = errors.New("quota exceeded")

// Quota represents a user's storage quota
type Quota struct {
	UserID       uuid.UUID `json:"user_id"`
	QuotaLimit   int64     `json:"quota_limit"`   // Total allowed bytes
	QuotaUsed    int64     `json:"quota_used"`    // Currently used bytes
	MessageCount int       `json:"message_count"` // Total message count
}

// QuotaPercent returns the percentage of quota used
func (q *Quota) QuotaPercent() float64 {
	if q.QuotaLimit <= 0 {
		return 0
	}
	return float64(q.QuotaUsed) / float64(q.QuotaLimit) * 100
}

// Available returns the available bytes
func (q *Quota) Available() int64 {
	if q.QuotaLimit <= 0 {
		return -1 // Unlimited
	}
	avail := q.QuotaLimit - q.QuotaUsed
	if avail < 0 {
		return 0
	}
	return avail
}

// IsExceeded returns true if quota is exceeded
func (q *Quota) IsExceeded() bool {
	if q.QuotaLimit <= 0 {
		return false // Unlimited
	}
	return q.QuotaUsed >= q.QuotaLimit
}

// WouldExceed returns true if adding size would exceed quota
func (q *Quota) WouldExceed(size int64) bool {
	if q.QuotaLimit <= 0 {
		return false // Unlimited
	}
	return q.QuotaUsed+size > q.QuotaLimit
}

// QuotaManager handles user quota operations
type QuotaManager struct {
	db          *database.DB
	logger      *slog.Logger
	warnPercent float64 // Percentage at which to warn (default 90)
}

// NewQuotaManager creates a new quota manager
func NewQuotaManager(db *database.DB, logger *slog.Logger) *QuotaManager {
	return &QuotaManager{
		db:          db,
		logger:      logger.With("component", "quota-manager"),
		warnPercent: 90,
	}
}

// SetWarnPercent sets the warning threshold percentage
func (m *QuotaManager) SetWarnPercent(percent float64) {
	m.warnPercent = percent
}

// GetQuota retrieves the quota for a user
func (m *QuotaManager) GetQuota(ctx context.Context, userID uuid.UUID) (*Quota, error) {
	// Use the user_quota view created in the migration
	query := `
		SELECT user_id, quota_limit, quota_used, message_count
		FROM user_quota
		WHERE user_id = $1
	`

	var q Quota
	err := m.db.Pool.QueryRow(ctx, query, userID).Scan(
		&q.UserID, &q.QuotaLimit, &q.QuotaUsed, &q.MessageCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get quota: %w", err)
	}

	return &q, nil
}

// CheckQuota checks if a user can store a message of the given size
// Returns nil if allowed, ErrQuotaExceeded if not
func (m *QuotaManager) CheckQuota(ctx context.Context, userID uuid.UUID, size int64) error {
	quota, err := m.GetQuota(ctx, userID)
	if err != nil {
		return err
	}

	if quota.WouldExceed(size) {
		m.logger.Warn("quota would be exceeded",
			"user_id", userID,
			"quota_limit", quota.QuotaLimit,
			"quota_used", quota.QuotaUsed,
			"message_size", size,
		)
		return ErrQuotaExceeded
	}

	// Check if approaching limit
	if quota.QuotaPercent() >= m.warnPercent {
		m.logger.Info("quota warning threshold reached",
			"user_id", userID,
			"percent_used", quota.QuotaPercent(),
		)
	}

	return nil
}

// UpdateUsedBytes updates the cached used_bytes in the users table
// This is called after storing or deleting messages
func (m *QuotaManager) UpdateUsedBytes(ctx context.Context, userID uuid.UUID, delta int64) error {
	query := `
		UPDATE users
		SET used_bytes = GREATEST(0, used_bytes + $1)
		WHERE id = $2
	`

	_, err := m.db.Pool.Exec(ctx, query, delta, userID)
	if err != nil {
		return fmt.Errorf("failed to update used bytes: %w", err)
	}

	return nil
}

// RecalculateQuota recalculates quota from actual message sizes
// This should be run periodically or after data recovery
func (m *QuotaManager) RecalculateQuota(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users u
		SET used_bytes = (
			SELECT COALESCE(SUM(m.size), 0)
			FROM mailboxes mb
			JOIN messages m ON m.mailbox_id = mb.id
			WHERE mb.user_id = u.id
		)
		WHERE u.id = $1
	`

	_, err := m.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to recalculate quota: %w", err)
	}

	m.logger.Info("quota recalculated", "user_id", userID)
	return nil
}

// RecalculateAllQuotas recalculates quota for all users
func (m *QuotaManager) RecalculateAllQuotas(ctx context.Context) error {
	query := `
		UPDATE users u
		SET used_bytes = (
			SELECT COALESCE(SUM(m.size), 0)
			FROM mailboxes mb
			JOIN messages m ON m.mailbox_id = mb.id
			WHERE mb.user_id = u.id
		)
	`

	result, err := m.db.Pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to recalculate all quotas: %w", err)
	}

	m.logger.Info("all quotas recalculated", "users_updated", result.RowsAffected())
	return nil
}

// SetQuotaLimit sets the quota limit for a user
func (m *QuotaManager) SetQuotaLimit(ctx context.Context, userID uuid.UUID, limit int64) error {
	query := `UPDATE users SET quota_bytes = $1 WHERE id = $2`

	result, err := m.db.Pool.Exec(ctx, query, limit, userID)
	if err != nil {
		return fmt.Errorf("failed to set quota limit: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	m.logger.Info("quota limit set",
		"user_id", userID,
		"limit", limit,
	)

	return nil
}

// GetQuotaReport generates a quota report for a user
type QuotaReport struct {
	Quota
	PercentUsed     float64            `json:"percent_used"`
	Available       int64              `json:"available"`
	IsExceeded      bool               `json:"is_exceeded"`
	IsWarning       bool               `json:"is_warning"`
	MailboxBreakdown map[string]int64  `json:"mailbox_breakdown"`
}

// GetQuotaReport generates a detailed quota report
func (m *QuotaManager) GetQuotaReport(ctx context.Context, userID uuid.UUID) (*QuotaReport, error) {
	quota, err := m.GetQuota(ctx, userID)
	if err != nil {
		return nil, err
	}

	report := &QuotaReport{
		Quota:       *quota,
		PercentUsed: quota.QuotaPercent(),
		Available:   quota.Available(),
		IsExceeded:  quota.IsExceeded(),
		IsWarning:   quota.QuotaPercent() >= m.warnPercent,
	}

	// Get breakdown by mailbox
	query := `
		SELECT mb.name, COALESCE(SUM(m.size), 0) as size
		FROM mailboxes mb
		LEFT JOIN messages m ON m.mailbox_id = mb.id
		WHERE mb.user_id = $1
		GROUP BY mb.id, mb.name
		ORDER BY size DESC
	`

	rows, err := m.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mailbox breakdown: %w", err)
	}
	defer rows.Close()

	report.MailboxBreakdown = make(map[string]int64)
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			return nil, err
		}
		report.MailboxBreakdown[name] = size
	}

	return report, nil
}

// GetUsersOverQuota returns users who are over their quota
func (m *QuotaManager) GetUsersOverQuota(ctx context.Context) ([]uuid.UUID, error) {
	query := `
		SELECT user_id FROM user_quota
		WHERE quota_limit > 0 AND quota_used >= quota_limit
	`

	rows, err := m.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get users over quota: %w", err)
	}
	defer rows.Close()

	var users []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}

	return users, nil
}

// GetUsersNearQuota returns users who are near their quota threshold
func (m *QuotaManager) GetUsersNearQuota(ctx context.Context, thresholdPercent float64) ([]uuid.UUID, error) {
	query := `
		SELECT user_id FROM user_quota
		WHERE quota_limit > 0
		AND (quota_used::float / quota_limit::float * 100) >= $1
	`

	rows, err := m.db.Pool.Query(ctx, query, thresholdPercent)
	if err != nil {
		return nil, fmt.Errorf("failed to get users near quota: %w", err)
	}
	defer rows.Close()

	var users []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}

	return users, nil
}
