package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Load reads configuration from file and environment
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read config file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	// Environment variables override
	v.SetEnvPrefix("ESP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// SMTP defaults
	v.SetDefault("server.smtp.enabled", true)
	v.SetDefault("server.smtp.listen_addr", ":25")
	v.SetDefault("server.smtp.submission_addr", ":587")
	v.SetDefault("server.smtp.implicit_tls_addr", ":465")
	v.SetDefault("server.smtp.max_message_size", 25*1024*1024) // 25MB
	v.SetDefault("server.smtp.max_recipients", 100)
	v.SetDefault("server.smtp.read_timeout", 60*time.Second)
	v.SetDefault("server.smtp.write_timeout", 60*time.Second)
	v.SetDefault("server.smtp.max_connections_per_ip", 10)
	v.SetDefault("server.smtp.max_messages_per_minute", 30)
	v.SetDefault("server.smtp.queue_workers", 4)
	v.SetDefault("server.smtp.max_retries", 7)
	v.SetDefault("server.smtp.bounce_after", 48*time.Hour)

	// IMAP defaults
	v.SetDefault("server.imap.enabled", true)
	v.SetDefault("server.imap.listen_addr", ":143")
	v.SetDefault("server.imap.implicit_tls_addr", ":993")
	v.SetDefault("server.imap.read_timeout", 30*time.Minute)
	v.SetDefault("server.imap.write_timeout", 60*time.Second)
	v.SetDefault("server.imap.idle_timeout", 30*time.Minute)
	v.SetDefault("server.imap.idle_poll_interval", 2*time.Minute)
	v.SetDefault("server.imap.max_connections", 1000)
	v.SetDefault("server.imap.max_connections_per_user", 10)

	// API defaults
	v.SetDefault("server.api.enabled", true)
	v.SetDefault("server.api.listen_addr", ":8080")
	v.SetDefault("server.api.jwt_expiry", 24*time.Hour)
	v.SetDefault("server.api.rate_limit", 100)
	v.SetDefault("server.api.enable_cors", false)

	// Database defaults
	v.SetDefault("storage.database.host", "localhost")
	v.SetDefault("storage.database.port", 5432)
	v.SetDefault("storage.database.database", "esp")
	v.SetDefault("storage.database.ssl_mode", "prefer")
	v.SetDefault("storage.database.max_connections", 25)
	v.SetDefault("storage.database.max_idle_conns", 5)
	v.SetDefault("storage.database.conn_max_lifetime", time.Hour)

	// Maildir defaults
	v.SetDefault("storage.maildir.base_path", "/var/mail/esp")
	v.SetDefault("storage.maildir.dir_mode", 0750)
	v.SetDefault("storage.maildir.file_mode", 0640)

	// TLS defaults
	v.SetDefault("security.tls.auto_tls", false)
	v.SetDefault("security.tls.acme_provider", "letsencrypt")
	v.SetDefault("security.tls.acme_staging", false)
	v.SetDefault("security.tls.acme_dir", "/var/lib/esp/certs")
	v.SetDefault("security.tls.renew_before", 720*time.Hour) // 30 days
	v.SetDefault("security.tls.check_interval", 24*time.Hour)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.add_source", false)

	// Filters defaults
	v.SetDefault("filters.enabled", true)
	v.SetDefault("filters.fail_open", true)
	v.SetDefault("filters.rspamd.enabled", false)
	v.SetDefault("filters.rspamd.url", "http://localhost:11333")
	v.SetDefault("filters.rspamd.timeout", 30*time.Second)
	v.SetDefault("filters.rspamd.reject_score", 15.0)
	v.SetDefault("filters.rspamd.quarantine_score", 6.0)
	v.SetDefault("filters.rspamd.add_headers", true)
	v.SetDefault("filters.clamav.enabled", false)
	v.SetDefault("filters.clamav.address", "tcp://localhost:3310")
	v.SetDefault("filters.clamav.timeout", 60*time.Second)
	v.SetDefault("filters.ratelimit.enabled", true)
	v.SetDefault("filters.ratelimit.ip_messages_per_minute", 30)
	v.SetDefault("filters.ratelimit.ip_messages_per_hour", 300)
	v.SetDefault("filters.ratelimit.sender_messages_per_minute", 10)
	v.SetDefault("filters.ratelimit.sender_messages_per_hour", 100)
	v.SetDefault("filters.ratelimit.recipient_messages_per_minute", 100)

	// LLM defaults
	v.SetDefault("filters.llm.enabled", false)
	v.SetDefault("filters.llm.provider", "openai")
	v.SetDefault("filters.llm.model", "gpt-4o-mini")
	v.SetDefault("filters.llm.min_confidence", 0.7)
	v.SetDefault("filters.llm.max_content_length", 4000)
	v.SetDefault("filters.llm.skip_spam", true)
	v.SetDefault("filters.llm.timeout", 30*time.Second)
	v.SetDefault("filters.llm.ollama.endpoint", "http://localhost:11434")

	// Events defaults
	v.SetDefault("events.workers", 4)
	v.SetDefault("events.queue_size", 1000)
	v.SetDefault("events.audit.enabled", true)
	v.SetDefault("events.audit.retention_days", 90)
	v.SetDefault("events.webhooks.enabled", true)
	v.SetDefault("events.webhooks.timeout", 30*time.Second)
	v.SetDefault("events.webhooks.max_retries", 5)
}
