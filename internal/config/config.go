package config

import "time"

// Config is the root configuration structure
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Filters  FiltersConfig  `mapstructure:"filters"`
	Events   EventsConfig   `mapstructure:"events"`
}

// ServerConfig contains all server-related settings
type ServerConfig struct {
	SMTP SMTPConfig `mapstructure:"smtp"`
	IMAP IMAPConfig `mapstructure:"imap"`
	API  APIConfig  `mapstructure:"api"`
}

// SMTPConfig defines SMTP server settings
type SMTPConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	ListenAddr      string        `mapstructure:"listen_addr"`
	SubmissionAddr  string        `mapstructure:"submission_addr"`
	ImplicitTLSAddr string        `mapstructure:"implicit_tls_addr"`
	Hostname        string        `mapstructure:"hostname"`
	MaxMessageSize  int64         `mapstructure:"max_message_size"`
	MaxRecipients   int           `mapstructure:"max_recipients"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	RequireTLS      bool          `mapstructure:"require_tls"`

	// Rate limiting
	MaxConnectionsPerIP   int `mapstructure:"max_connections_per_ip"`
	MaxMessagesPerMinute  int `mapstructure:"max_messages_per_minute"`

	// Queue settings
	QueueWorkers   int           `mapstructure:"queue_workers"`
	RetryIntervals []string      `mapstructure:"retry_intervals"`
	MaxRetries     int           `mapstructure:"max_retries"`
	BounceAfter    time.Duration `mapstructure:"bounce_after"`
}

// IMAPConfig defines IMAP server settings
type IMAPConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	ListenAddr        string        `mapstructure:"listen_addr"`
	ImplicitTLSAddr   string        `mapstructure:"implicit_tls_addr"`
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	IdlePollInterval  time.Duration `mapstructure:"idle_poll_interval"`
	MaxConnections    int           `mapstructure:"max_connections"`
	MaxConnectionsPerUser int       `mapstructure:"max_connections_per_user"`
}

// APIConfig defines REST API settings
type APIConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	ListenAddr  string        `mapstructure:"listen_addr"`
	JWTSecret   string        `mapstructure:"jwt_secret"`
	JWTExpiry   time.Duration `mapstructure:"jwt_expiry"`
	APIKey      string        `mapstructure:"api_key"`
	RateLimit   int           `mapstructure:"rate_limit"`
	EnableCORS  bool          `mapstructure:"enable_cors"`
	CORSOrigins []string      `mapstructure:"cors_origins"`
}

// StorageConfig defines storage settings
type StorageConfig struct {
	Database DatabaseConfig `mapstructure:"database"`
	Maildir  MaildirConfig  `mapstructure:"maildir"`
}

// DatabaseConfig defines PostgreSQL settings
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Database        string        `mapstructure:"database"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxConnections  int           `mapstructure:"max_connections"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// MaildirConfig defines maildir storage settings
type MaildirConfig struct {
	BasePath string `mapstructure:"base_path"`
	DirMode  uint32 `mapstructure:"dir_mode"`
	FileMode uint32 `mapstructure:"file_mode"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	TLS TLSConfig `mapstructure:"tls"`
}

// TLSConfig defines TLS/certificate settings
type TLSConfig struct {
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
	AutoTLS        bool   `mapstructure:"auto_tls"`
	ACMEEmail      string `mapstructure:"acme_email"`
	ACMEProvider   string `mapstructure:"acme_provider"`
	ACMEDir        string `mapstructure:"acme_dir"`
	ACMEStaging    bool   `mapstructure:"acme_staging"`
	ZeroSSLEABKID  string `mapstructure:"zerossl_eab_kid"`
	ZeroSSLEABKey  string `mapstructure:"zerossl_eab_key"`
	RenewBefore    time.Duration `mapstructure:"renew_before"`
	CheckInterval  time.Duration `mapstructure:"check_interval"`
	DKIM           DKIMConfig    `mapstructure:"dkim"`
}

// DKIMConfig defines DKIM signing settings
type DKIMConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	KeyPath  string `mapstructure:"key_path"`  // Path pattern, e.g., /var/lib/rspamd/dkim/$domain.$selector.key
	Selector string `mapstructure:"selector"`  // DKIM selector, typically "default"
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level     string `mapstructure:"level"`
	Format    string `mapstructure:"format"`
	Output    string `mapstructure:"output"`
	AddSource bool   `mapstructure:"add_source"`
}

// FiltersConfig defines filter pipeline settings
type FiltersConfig struct {
	Enabled   bool              `mapstructure:"enabled"`
	FailOpen  bool              `mapstructure:"fail_open"`
	Rspamd    RspamdConfig      `mapstructure:"rspamd"`
	ClamAV    ClamAVConfig      `mapstructure:"clamav"`
	RateLimit RateLimitConfig   `mapstructure:"ratelimit"`
	LLM       LLMConfig         `mapstructure:"llm"`
}

// RspamdConfig for rspamd integration
type RspamdConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	URL             string        `mapstructure:"url"`
	Password        string        `mapstructure:"password"`
	Timeout         time.Duration `mapstructure:"timeout"`
	RejectScore     float64       `mapstructure:"reject_score"`
	QuarantineScore float64       `mapstructure:"quarantine_score"`
	AddHeaders      bool          `mapstructure:"add_headers"`
}

// ClamAVConfig for ClamAV integration
type ClamAVConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Address string        `mapstructure:"address"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// RateLimitConfig for rate limiting
type RateLimitConfig struct {
	Enabled                    bool `mapstructure:"enabled"`
	IPMessagesPerMinute        int  `mapstructure:"ip_messages_per_minute"`
	IPMessagesPerHour          int  `mapstructure:"ip_messages_per_hour"`
	SenderMessagesPerMinute    int  `mapstructure:"sender_messages_per_minute"`
	SenderMessagesPerHour      int  `mapstructure:"sender_messages_per_hour"`
	RecipientMessagesPerMinute int  `mapstructure:"recipient_messages_per_minute"`
}

// LLMConfig for LLM integration
type LLMConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	Provider         string        `mapstructure:"provider"`
	Model            string        `mapstructure:"model"`
	MinConfidence    float64       `mapstructure:"min_confidence"`
	MaxContentLength int           `mapstructure:"max_content_length"`
	SkipSpam         bool          `mapstructure:"skip_spam"`
	Timeout          time.Duration `mapstructure:"timeout"`
	OpenAI           OpenAIConfig  `mapstructure:"openai"`
	Anthropic        AnthropicConfig `mapstructure:"anthropic"`
	Ollama           OllamaConfig  `mapstructure:"ollama"`
	Categories       []CategoryConfig `mapstructure:"categories"`
}

// OpenAIConfig for OpenAI
type OpenAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	OrgID   string `mapstructure:"org_id"`
	BaseURL string `mapstructure:"base_url"`
}

// AnthropicConfig for Anthropic
type AnthropicConfig struct {
	APIKey string `mapstructure:"api_key"`
}

// OllamaConfig for Ollama
type OllamaConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

// CategoryConfig for LLM categories
type CategoryConfig struct {
	Name        string   `mapstructure:"name"`
	Description string   `mapstructure:"description"`
	Examples    []string `mapstructure:"examples"`
	Folder      string   `mapstructure:"folder"`
	Priority    int      `mapstructure:"priority"`
}

// EventsConfig defines event system settings
type EventsConfig struct {
	Workers   int `mapstructure:"workers"`
	QueueSize int `mapstructure:"queue_size"`
	Audit     AuditConfig `mapstructure:"audit"`
	Webhooks  WebhooksConfig `mapstructure:"webhooks"`
}

// AuditConfig for audit logging
type AuditConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	RetentionDays int  `mapstructure:"retention_days"`
}

// WebhooksConfig for webhook settings
type WebhooksConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	Timeout     time.Duration `mapstructure:"timeout"`
	MaxRetries  int           `mapstructure:"max_retries"`
	RetryDelays []string      `mapstructure:"retry_delays"`
}
