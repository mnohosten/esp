package api

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-playground/validator/v10"
)

// Config holds API server configuration.
type Config struct {
	ListenAddr  string        `mapstructure:"listen_addr"`
	JWTSecret   string        `mapstructure:"jwt_secret"`
	JWTExpiry   time.Duration `mapstructure:"jwt_expiry"`
	EnableCORS  bool          `mapstructure:"enable_cors"`
	CORSOrigins []string      `mapstructure:"cors_origins"`
	RateLimit   int           `mapstructure:"rate_limit"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:  ":8080",
		JWTSecret:   "change-me-in-production",
		JWTExpiry:   24 * time.Hour,
		EnableCORS:  true,
		CORSOrigins: []string{"*"},
		RateLimit:   100,
	}
}

// Server is the REST API server.
type Server struct {
	router     chi.Router
	config     Config
	db         *sql.DB
	logger     *slog.Logger
	httpServer *http.Server
	jwtAuth    *JWTAuth
	validator  *validator.Validate
	startTime  time.Time
}

// New creates a new API server.
func New(cfg Config, db *sql.DB, logger *slog.Logger) *Server {
	s := &Server{
		config:    cfg,
		db:        db,
		logger:    logger,
		jwtAuth:   NewJWTAuth(cfg.JWTSecret, cfg.JWTExpiry),
		validator: validator.New(),
		startTime: time.Now(),
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures all routes.
func (s *Server) setupRoutes() {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(middleware.Compress(5))

	// CORS if enabled
	if s.config.EnableCORS {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   s.config.CORSOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// Health check (no auth)
	r.Get("/health", s.handleHealth)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Auth routes (no auth required)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.handleLogin)
			r.Post("/refresh", s.handleRefresh)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(s.jwtAuth.Middleware)

			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/logout", s.handleLogout)

			// Domain management (admin only)
			r.Route("/domains", func(r chi.Router) {
				r.Use(AdminMiddleware)
				r.Get("/", s.handleListDomains)
				r.Post("/", s.handleCreateDomain)
				r.Get("/{domainID}", s.handleGetDomain)
				r.Put("/{domainID}", s.handleUpdateDomain)
				r.Delete("/{domainID}", s.handleDeleteDomain)
				r.Get("/{domainID}/dns", s.handleGetDNSRecords)
				r.Post("/{domainID}/dkim/rotate", s.handleRotateDKIM)
			})

			// User management
			r.Route("/users", func(r chi.Router) {
				r.Get("/", s.handleListUsers)
				r.With(AdminMiddleware).Post("/", s.handleCreateUser)
				r.Get("/{userID}", s.handleGetUser)
				r.Put("/{userID}", s.handleUpdateUser)
				r.With(AdminMiddleware).Delete("/{userID}", s.handleDeleteUser)
				r.Put("/{userID}/password", s.handleChangePassword)
				r.Get("/{userID}/quota", s.handleGetQuota)
			})

			// Alias management
			r.Route("/aliases", func(r chi.Router) {
				r.Use(AdminMiddleware)
				r.Get("/", s.handleListAliases)
				r.Post("/", s.handleCreateAlias)
				r.Get("/{aliasID}", s.handleGetAlias)
				r.Put("/{aliasID}", s.handleUpdateAlias)
				r.Delete("/{aliasID}", s.handleDeleteAlias)
			})

			// Mailbox management
			r.Route("/mailboxes", func(r chi.Router) {
				r.Get("/", s.handleListMailboxes)
				r.Post("/", s.handleCreateMailbox)
				r.Get("/{mailboxID}", s.handleGetMailbox)
				r.Put("/{mailboxID}", s.handleUpdateMailbox)
				r.Delete("/{mailboxID}", s.handleDeleteMailbox)
				r.Get("/{mailboxID}/messages", s.handleListMessages)
			})

			// Message management
			r.Route("/messages", func(r chi.Router) {
				r.Get("/{messageID}", s.handleGetMessage)
				r.Get("/{messageID}/raw", s.handleGetRawMessage)
				r.Put("/{messageID}/flags", s.handleUpdateFlags)
				r.Post("/{messageID}/move", s.handleMoveMessage)
				r.Delete("/{messageID}", s.handleDeleteMessage)
			})

			// Queue management (admin only)
			r.Route("/queue", func(r chi.Router) {
				r.Use(AdminMiddleware)
				r.Get("/", s.handleListQueue)
				r.Get("/{queueID}", s.handleGetQueueItem)
				r.Delete("/{queueID}", s.handleCancelQueue)
				r.Post("/{queueID}/retry", s.handleRetryQueue)
			})

			// Statistics
			r.Route("/stats", func(r chi.Router) {
				r.Get("/overview", s.handleStatsOverview)
				r.Get("/messages", s.handleStatsMessages)
				r.Get("/queue", s.handleStatsQueue)
			})
		})

		// Admin routes
		r.Route("/admin", func(r chi.Router) {
			r.Use(s.jwtAuth.Middleware)
			r.Use(AdminMiddleware)
			r.Get("/health", s.handleAdminHealth)
			r.Post("/reload", s.handleReload)
		})
	})

	s.router = r
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("starting API server", "addr", s.config.ListenAddr)

	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.Stop(context.Background())
	}
}

// Stop gracefully stops the server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping API server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(shutdownCtx)
}

// Router returns the router for testing.
func (s *Server) Router() chi.Router {
	return s.router
}
