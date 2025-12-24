package config

import (
	"errors"
	"fmt"
	"net"
)

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	var errs []error

	// Validate SMTP config
	if c.Server.SMTP.Enabled {
		if err := validateAddr(c.Server.SMTP.ListenAddr, "server.smtp.listen_addr"); err != nil {
			errs = append(errs, err)
		}
		if c.Server.SMTP.Hostname == "" {
			errs = append(errs, errors.New("server.smtp.hostname is required when SMTP is enabled"))
		}
		if c.Server.SMTP.MaxMessageSize <= 0 {
			errs = append(errs, errors.New("server.smtp.max_message_size must be positive"))
		}
		if c.Server.SMTP.MaxRecipients <= 0 {
			errs = append(errs, errors.New("server.smtp.max_recipients must be positive"))
		}
	}

	// Validate IMAP config
	if c.Server.IMAP.Enabled {
		if err := validateAddr(c.Server.IMAP.ListenAddr, "server.imap.listen_addr"); err != nil {
			errs = append(errs, err)
		}
	}

	// Validate API config
	if c.Server.API.Enabled {
		if err := validateAddr(c.Server.API.ListenAddr, "server.api.listen_addr"); err != nil {
			errs = append(errs, err)
		}
		if c.Server.API.JWTSecret == "" {
			errs = append(errs, errors.New("server.api.jwt_secret is required when API is enabled"))
		}
		if len(c.Server.API.JWTSecret) < 32 {
			errs = append(errs, errors.New("server.api.jwt_secret should be at least 32 characters"))
		}
	}

	// Validate database config
	if c.Storage.Database.Host == "" {
		errs = append(errs, errors.New("storage.database.host is required"))
	}
	if c.Storage.Database.Port <= 0 || c.Storage.Database.Port > 65535 {
		errs = append(errs, errors.New("storage.database.port must be between 1 and 65535"))
	}
	if c.Storage.Database.User == "" {
		errs = append(errs, errors.New("storage.database.user is required"))
	}
	if c.Storage.Database.Database == "" {
		errs = append(errs, errors.New("storage.database.database is required"))
	}

	// Validate maildir config
	if c.Storage.Maildir.BasePath == "" {
		errs = append(errs, errors.New("storage.maildir.base_path is required"))
	}

	// Validate TLS config
	if c.Security.TLS.AutoTLS {
		if c.Security.TLS.ACMEEmail == "" {
			errs = append(errs, errors.New("security.tls.acme_email is required when auto_tls is enabled"))
		}
		if c.Security.TLS.ACMEDir == "" {
			errs = append(errs, errors.New("security.tls.acme_dir is required when auto_tls is enabled"))
		}
	} else if c.Security.TLS.CertFile != "" || c.Security.TLS.KeyFile != "" {
		// If manual TLS is configured, both files are required
		if c.Security.TLS.CertFile == "" {
			errs = append(errs, errors.New("security.tls.cert_file is required when key_file is set"))
		}
		if c.Security.TLS.KeyFile == "" {
			errs = append(errs, errors.New("security.tls.key_file is required when cert_file is set"))
		}
	}

	// Validate LLM config
	if c.Filters.LLM.Enabled {
		switch c.Filters.LLM.Provider {
		case "openai":
			if c.Filters.LLM.OpenAI.APIKey == "" {
				errs = append(errs, errors.New("filters.llm.openai.api_key is required when provider is openai"))
			}
		case "anthropic":
			if c.Filters.LLM.Anthropic.APIKey == "" {
				errs = append(errs, errors.New("filters.llm.anthropic.api_key is required when provider is anthropic"))
			}
		case "ollama":
			// Ollama doesn't require API key, just endpoint
			if c.Filters.LLM.Ollama.Endpoint == "" {
				errs = append(errs, errors.New("filters.llm.ollama.endpoint is required when provider is ollama"))
			}
		default:
			errs = append(errs, fmt.Errorf("filters.llm.provider must be one of: openai, anthropic, ollama (got: %s)", c.Filters.LLM.Provider))
		}
	}

	// Validate logging config
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
		// Valid
	default:
		errs = append(errs, fmt.Errorf("logging.level must be one of: debug, info, warn, error (got: %s)", c.Logging.Level))
	}

	switch c.Logging.Format {
	case "json", "text":
		// Valid
	default:
		errs = append(errs, fmt.Errorf("logging.format must be one of: json, text (got: %s)", c.Logging.Format))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateAddr(addr, name string) error {
	if addr == "" {
		return fmt.Errorf("%s is required", name)
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	return nil
}
