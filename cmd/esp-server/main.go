// Package main provides the entry point for the ESP server.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"

	"github.com/mnohosten/esp/internal/api"
	"github.com/mnohosten/esp/internal/config"
	"github.com/mnohosten/esp/internal/database"
	"github.com/mnohosten/esp/internal/imap"
	"github.com/mnohosten/esp/internal/logging"
	"github.com/mnohosten/esp/internal/mailbox"
	smtppkg "github.com/mnohosten/esp/internal/smtp"
	"github.com/mnohosten/esp/internal/storage/maildir"
	tlspkg "github.com/mnohosten/esp/internal/tls"
	"github.com/mnohosten/esp/internal/version"
)

var (
	configFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "esp-server",
		Short: "ESP - Email Service Platform",
		Long:  "Enterprise-grade email server with SMTP, IMAP, and REST API support.",
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path")

	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(migrateCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the ESP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer()
		},
	}
}

func migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrations()
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showMigrationStatus()
		},
	})

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ESP Server %s\n", version.Version)
			fmt.Printf("Commit: %s\n", version.Commit)
			fmt.Printf("Built: %s\n", version.BuildTime)
		},
	}
}

func runServer() error {
	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := logging.New(cfg.Logging)
	logger.Info("starting ESP server",
		"version", version.Version,
		"config", configFile,
	)

	// Connect to database
	ctx := context.Background()
	db, err := database.New(ctx, cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	logger.Info("connected to database",
		"host", cfg.Storage.Database.Host,
		"database", cfg.Storage.Database.Database,
	)

	// Load TLS config if configured
	tlsConfig, err := tlspkg.LoadConfig(cfg.Security.TLS)
	if err != nil {
		return fmt.Errorf("failed to load TLS config: %w", err)
	}
	if tlsConfig != nil {
		logger.Info("TLS configured",
			"cert_file", cfg.Security.TLS.CertFile,
		)
	}

	// Initialize Maildir storage
	maildirStore, err := maildir.New(cfg.Storage.Maildir, db, cfg.Server.SMTP.Hostname, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize maildir: %w", err)
	}

	// Initialize mailbox components
	mailboxMgr := mailbox.NewManager(db, maildirStore, logger)
	messageStore := mailbox.NewMessageStore(db, maildirStore, mailboxMgr, logger)
	searcher := mailbox.NewSearcher(db)
	quotaMgr := mailbox.NewQuotaManager(db, logger)

	// Create cancellable context for shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start SMTP server if enabled
	if cfg.Server.SMTP.Enabled {
		// Create database-backed authenticator for SMTP
		dbAuth := smtppkg.NewDBUserAuth(db)
		smtpAuth := smtppkg.NewAuthenticator(dbAuth, logger)
		smtpBackend := smtppkg.NewBackend(cfg.Server.SMTP, logger, smtppkg.WithAuthenticator(smtpAuth))
		smtpServer := smtppkg.New(cfg.Server.SMTP, smtpBackend, tlsConfig, logger)
		if err := smtpServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start SMTP server: %w", err)
		}
		defer smtpServer.Stop(ctx)
	}

	// Start IMAP server if enabled
	if cfg.Server.IMAP.Enabled {
		imapBackend := imap.NewBackend(db, mailboxMgr, messageStore, searcher, quotaMgr, maildirStore, logger)
		imapServer := imap.New(cfg.Server.IMAP, imapBackend, tlsConfig, logger)
		if err := imapServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start IMAP server: %w", err)
		}
		defer imapServer.Stop(ctx)
	}

	// Start API server if enabled
	if cfg.Server.API.Enabled {
		// Create stdlib sql.DB from pgx pool for API server
		sqlDB, err := sql.Open("pgx", fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Storage.Database.Host, cfg.Storage.Database.Port,
			cfg.Storage.Database.User, cfg.Storage.Database.Password,
			cfg.Storage.Database.Database, cfg.Storage.Database.SSLMode,
		))
		if err != nil {
			return fmt.Errorf("failed to create sql.DB: %w", err)
		}
		defer sqlDB.Close()

		apiCfg := api.Config{
			ListenAddr:  cfg.Server.API.ListenAddr,
			JWTSecret:   cfg.Server.API.JWTSecret,
			JWTExpiry:   cfg.Server.API.JWTExpiry,
			EnableCORS:  cfg.Server.API.EnableCORS,
			CORSOrigins: cfg.Server.API.CORSOrigins,
			RateLimit:   cfg.Server.API.RateLimit,
		}
		apiServer := api.New(apiCfg, sqlDB, logger)
		go func() {
			if err := apiServer.Start(ctx); err != nil {
				logger.Error("API server error", "error", err)
			}
		}()
		defer apiServer.Stop(ctx)
	}

	logger.Info("ESP server started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down...")
	cancel()

	return nil
}

func runMigrations() error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger := logging.New(cfg.Logging)

	ctx := context.Background()
	db, err := database.New(ctx, cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	return db.Migrate(ctx, &database.MigrateOptions{Logger: logger})
}

func showMigrationStatus() error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ctx := context.Background()
	db, err := database.New(ctx, cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	status, err := db.MigrationStatus(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Migration Status:")
	fmt.Println("-----------------")
	for _, m := range status {
		state := "pending"
		if m.Applied {
			state = fmt.Sprintf("applied at %s", m.AppliedAt)
		}
		fmt.Printf("  %s: %s\n", m.Version, state)
	}

	return nil
}
