package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrateOptions configures migration behavior
type MigrateOptions struct {
	Logger *slog.Logger
}

// Migrate runs all pending migrations
func (db *DB) Migrate(ctx context.Context, opts *MigrateOptions) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Create migrations table if not exists
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	applied := make(map[string]bool)
	rows, err := db.Pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("failed to scan migration: %w", err)
		}
		applied[version] = true
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error reading migrations: %w", err)
	}

	// Get migration files
	files, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations: %w", err)
	}

	var migrations []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			migrations = append(migrations, f.Name())
		}
	}
	sort.Strings(migrations)

	// Apply pending migrations
	appliedCount := 0
	for _, migration := range migrations {
		version := strings.TrimSuffix(migration, filepath.Ext(migration))
		if applied[version] {
			logger.Debug("skipping applied migration", "version", version)
			continue
		}

		logger.Info("applying migration", "version", version)

		content, err := fs.ReadFile(migrationsFS, filepath.Join("migrations", migration))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", migration, err)
		}

		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.Exec(ctx, string(content)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to apply migration %s: %w", migration, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to record migration %s: %w", migration, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", migration, err)
		}

		logger.Info("applied migration", "version", version)
		appliedCount++
	}

	if appliedCount == 0 {
		logger.Info("no pending migrations")
	} else {
		logger.Info("migrations completed", "applied", appliedCount)
	}

	return nil
}

// MigrationStatus returns the status of all migrations
func (db *DB) MigrationStatus(ctx context.Context) ([]MigrationInfo, error) {
	// Get applied migrations
	applied := make(map[string]string)
	rows, err := db.Pool.Query(ctx, "SELECT version, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var version, appliedAt string
		if err := rows.Scan(&version, &appliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration: %w", err)
		}
		applied[version] = appliedAt
	}

	// Get all migration files
	files, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations: %w", err)
	}

	var status []MigrationInfo
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		version := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
		info := MigrationInfo{
			Version: version,
			File:    f.Name(),
		}
		if appliedAt, ok := applied[version]; ok {
			info.Applied = true
			info.AppliedAt = appliedAt
		}
		status = append(status, info)
	}

	sort.Slice(status, func(i, j int) bool {
		return status[i].Version < status[j].Version
	})

	return status, nil
}

// MigrationInfo describes a migration
type MigrationInfo struct {
	Version   string `json:"version"`
	File      string `json:"file"`
	Applied   bool   `json:"applied"`
	AppliedAt string `json:"applied_at,omitempty"`
}
