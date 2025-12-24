package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrQueueClosed is returned when operations are attempted on a closed queue.
	ErrQueueClosed = errors.New("queue is closed")

	// ErrMessageNotFound is returned when a message is not found.
	ErrMessageNotFound = errors.New("message not found")
)

// ManagerConfig holds configuration for the queue manager.
type ManagerConfig struct {
	Workers        int
	RetryIntervals []time.Duration
	MaxRetries     int
	BounceAfter    time.Duration
	PollInterval   time.Duration
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		Workers: 4,
		RetryIntervals: []time.Duration{
			5 * time.Minute,
			15 * time.Minute,
			30 * time.Minute,
			1 * time.Hour,
			4 * time.Hour,
			8 * time.Hour,
			24 * time.Hour,
		},
		MaxRetries:   7,
		BounceAfter:  48 * time.Hour,
		PollInterval: 10 * time.Second,
	}
}

// Manager handles the outbound email queue.
type Manager struct {
	pool   *pgxpool.Pool
	config ManagerConfig
	logger *slog.Logger

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewManager creates a new queue manager.
func NewManager(pool *pgxpool.Pool, config ManagerConfig, logger *slog.Logger) *Manager {
	return &Manager{
		pool:   pool,
		config: config,
		logger: logger.With("component", "queue"),
		stopCh: make(chan struct{}),
	}
}

// Enqueue adds a message to the queue.
func (m *Manager) Enqueue(ctx context.Context, msg *Message, opts EnqueueOptions) error {
	m.mu.RLock()
	if !m.running {
		m.mu.RUnlock()
		// Allow enqueueing even when not running (for testing or deferred start)
	} else {
		m.mu.RUnlock()
	}

	query := `
		INSERT INTO queue (
			message_id, sender, recipient, message_path, size,
			status, priority, next_attempt, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`

	var id string
	var createdAt time.Time

	err := m.pool.QueryRow(ctx, query,
		msg.MessageID,
		msg.Sender,
		msg.Recipient,
		msg.MessagePath,
		msg.Size,
		StatusPending,
		opts.Priority,
		opts.DelayUntil,
		opts.ExpiresAt,
	).Scan(&id, &createdAt)

	if err != nil {
		return fmt.Errorf("failed to enqueue message: %w", err)
	}

	msg.ID = id
	msg.CreatedAt = createdAt
	msg.Status = StatusPending
	msg.Priority = opts.Priority
	msg.NextAttempt = opts.DelayUntil
	msg.ExpiresAt = opts.ExpiresAt

	m.logger.Info("message enqueued",
		"id", id,
		"sender", msg.Sender,
		"recipient", msg.Recipient,
	)

	return nil
}

// Dequeue retrieves the next message to process.
// It marks the message as processing atomically.
func (m *Manager) Dequeue(ctx context.Context) (*Message, error) {
	query := `
		UPDATE queue
		SET status = $1, last_attempt = NOW()
		WHERE id = (
			SELECT id FROM queue
			WHERE status IN ($2, $3)
			AND next_attempt <= NOW()
			AND (expires_at IS NULL OR expires_at > NOW())
			ORDER BY priority DESC, next_attempt ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, COALESCE(message_id, ''), sender, recipient,
			COALESCE(message_path, ''), COALESCE(size, 0),
			status, priority, COALESCE(attempts, 0),
			COALESCE(last_attempt, NOW()), COALESCE(next_attempt, NOW()),
			COALESCE(last_error, ''),
			created_at, COALESCE(expires_at, NOW() + INTERVAL '48 hours')
	`

	msg := &Message{}
	err := m.pool.QueryRow(ctx, query, StatusProcessing, StatusPending, StatusDeferred).Scan(
		&msg.ID,
		&msg.MessageID,
		&msg.Sender,
		&msg.Recipient,
		&msg.MessagePath,
		&msg.Size,
		&msg.Status,
		&msg.Priority,
		&msg.Attempts,
		&msg.LastAttempt,
		&msg.NextAttempt,
		&msg.LastError,
		&msg.CreatedAt,
		&msg.ExpiresAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No messages available
		}
		return nil, fmt.Errorf("failed to dequeue message: %w", err)
	}

	return msg, nil
}

// Complete marks a message as delivered and removes it from the queue.
func (m *Manager) Complete(ctx context.Context, msgID string) error {
	query := `DELETE FROM queue WHERE id = $1`

	result, err := m.pool.Exec(ctx, query, msgID)
	if err != nil {
		return fmt.Errorf("failed to complete message: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMessageNotFound
	}

	m.logger.Info("message delivered", "id", msgID)
	return nil
}

// Defer reschedules a message for later retry.
func (m *Manager) Defer(ctx context.Context, msgID string, result *DeliveryResult) error {
	// Get current attempt count
	var attempts int
	err := m.pool.QueryRow(ctx, "SELECT attempts FROM queue WHERE id = $1", msgID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMessageNotFound
		}
		return fmt.Errorf("failed to get message: %w", err)
	}

	attempts++

	// Calculate next retry time
	var nextAttempt time.Time
	if attempts <= len(m.config.RetryIntervals) {
		nextAttempt = time.Now().Add(m.config.RetryIntervals[attempts-1])
	} else if attempts <= m.config.MaxRetries {
		// Use last interval for remaining retries
		nextAttempt = time.Now().Add(m.config.RetryIntervals[len(m.config.RetryIntervals)-1])
	} else {
		// Max retries exceeded - mark as bounced
		return m.Bounce(ctx, msgID, result.Error)
	}

	query := `
		UPDATE queue
		SET status = $1, attempts = $2, next_attempt = $3, last_error = $4
		WHERE id = $5
	`

	_, err = m.pool.Exec(ctx, query, StatusDeferred, attempts, nextAttempt, result.Error, msgID)
	if err != nil {
		return fmt.Errorf("failed to defer message: %w", err)
	}

	m.logger.Info("message deferred",
		"id", msgID,
		"attempts", attempts,
		"next_attempt", nextAttempt,
		"error", result.Error,
	)

	return nil
}

// Bounce marks a message as permanently failed.
func (m *Manager) Bounce(ctx context.Context, msgID string, reason string) error {
	query := `
		UPDATE queue
		SET status = $1, last_error = $2
		WHERE id = $3
	`

	result, err := m.pool.Exec(ctx, query, StatusBounced, reason, msgID)
	if err != nil {
		return fmt.Errorf("failed to bounce message: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMessageNotFound
	}

	m.logger.Warn("message bounced", "id", msgID, "reason", reason)
	return nil
}

// Fail marks a message as failed (temporary).
func (m *Manager) Fail(ctx context.Context, msgID string, reason string) error {
	query := `
		UPDATE queue
		SET status = $1, last_error = $2
		WHERE id = $3
	`

	result, err := m.pool.Exec(ctx, query, StatusFailed, reason, msgID)
	if err != nil {
		return fmt.Errorf("failed to fail message: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMessageNotFound
	}

	m.logger.Error("message failed", "id", msgID, "reason", reason)
	return nil
}

// GetMessage retrieves a message by ID.
func (m *Manager) GetMessage(ctx context.Context, msgID string) (*Message, error) {
	query := `
		SELECT id, COALESCE(message_id, ''), sender, recipient,
			COALESCE(message_path, ''), COALESCE(size, 0),
			status, priority, COALESCE(attempts, 0),
			COALESCE(last_attempt, NOW()), COALESCE(next_attempt, NOW()),
			COALESCE(last_error, ''),
			created_at, COALESCE(expires_at, NOW() + INTERVAL '48 hours')
		FROM queue WHERE id = $1
	`

	msg := &Message{}
	err := m.pool.QueryRow(ctx, query, msgID).Scan(
		&msg.ID,
		&msg.MessageID,
		&msg.Sender,
		&msg.Recipient,
		&msg.MessagePath,
		&msg.Size,
		&msg.Status,
		&msg.Priority,
		&msg.Attempts,
		&msg.LastAttempt,
		&msg.NextAttempt,
		&msg.LastError,
		&msg.CreatedAt,
		&msg.ExpiresAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("failed to get message: %w", err)
	}

	return msg, nil
}

// ListPending returns pending messages.
func (m *Manager) ListPending(ctx context.Context, limit int) ([]*Message, error) {
	query := `
		SELECT id, COALESCE(message_id, ''), sender, recipient,
			COALESCE(message_path, ''), COALESCE(size, 0),
			status, priority, COALESCE(attempts, 0),
			COALESCE(last_attempt, NOW()), COALESCE(next_attempt, NOW()),
			COALESCE(last_error, ''),
			created_at, COALESCE(expires_at, NOW() + INTERVAL '48 hours')
		FROM queue
		WHERE status IN ($1, $2)
		ORDER BY priority DESC, next_attempt ASC
		LIMIT $3
	`

	rows, err := m.pool.Query(ctx, query, StatusPending, StatusDeferred, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg := &Message{}
		err := rows.Scan(
			&msg.ID,
			&msg.MessageID,
			&msg.Sender,
			&msg.Recipient,
			&msg.MessagePath,
			&msg.Size,
			&msg.Status,
			&msg.Priority,
			&msg.Attempts,
			&msg.LastAttempt,
			&msg.NextAttempt,
			&msg.LastError,
			&msg.CreatedAt,
			&msg.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// Stats returns queue statistics.
func (m *Manager) Stats(ctx context.Context) (map[Status]int, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM queue
		GROUP BY status
	`

	rows, err := m.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get queue stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[Status]int)
	for rows.Next() {
		var status Status
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan stats: %w", err)
		}
		stats[status] = count
	}

	return stats, rows.Err()
}

// CleanExpired removes expired messages from the queue.
func (m *Manager) CleanExpired(ctx context.Context) (int, error) {
	query := `
		DELETE FROM queue
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		AND status NOT IN ($1, $2)
	`

	result, err := m.pool.Exec(ctx, query, StatusDelivered, StatusBounced)
	if err != nil {
		return 0, fmt.Errorf("failed to clean expired messages: %w", err)
	}

	count := int(result.RowsAffected())
	if count > 0 {
		m.logger.Info("cleaned expired messages", "count", count)
	}

	return count, nil
}

// ResetStale resets messages stuck in processing state.
func (m *Manager) ResetStale(ctx context.Context, staleAfter time.Duration) (int, error) {
	query := `
		UPDATE queue
		SET status = $1
		WHERE status = $2
		AND last_attempt < $3
	`

	result, err := m.pool.Exec(ctx, query, StatusPending, StatusProcessing, time.Now().Add(-staleAfter))
	if err != nil {
		return 0, fmt.Errorf("failed to reset stale messages: %w", err)
	}

	count := int(result.RowsAffected())
	if count > 0 {
		m.logger.Warn("reset stale messages", "count", count)
	}

	return count, nil
}

// Start starts the queue manager workers.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("queue manager already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.logger.Info("starting queue manager", "workers", m.config.Workers)

	// Start maintenance goroutine
	m.wg.Add(1)
	go m.maintenanceLoop(ctx)

	return nil
}

// Stop gracefully stops the queue manager.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	m.logger.Info("stopping queue manager")

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("queue manager stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// maintenanceLoop runs periodic maintenance tasks.
func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Clean expired messages
			if _, err := m.CleanExpired(ctx); err != nil {
				m.logger.Error("failed to clean expired messages", "error", err)
			}

			// Reset stale messages (stuck in processing for > 30 minutes)
			if _, err := m.ResetStale(ctx, 30*time.Minute); err != nil {
				m.logger.Error("failed to reset stale messages", "error", err)
			}
		}
	}
}

// Running returns whether the manager is running.
func (m *Manager) Running() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}
