package llm

import (
	"fmt"
	"log/slog"
)

// NewClient creates an LLM client based on configuration.
func NewClient(cfg Config, logger *slog.Logger) (Client, error) {
	if cfg.Provider == "" {
		return nil, fmt.Errorf("llm provider not configured")
	}

	switch cfg.Provider {
	case "openai":
		return NewOpenAI(cfg, logger)
	case "anthropic":
		return NewAnthropic(cfg, logger)
	case "ollama":
		return NewOllama(cfg, logger)
	default:
		return nil, fmt.Errorf("unknown LLM provider: %s", cfg.Provider)
	}
}

// NewClientWithFallback creates an LLM client with fallback support.
// If the primary provider fails, it returns nil without error.
func NewClientWithFallback(cfg Config, logger *slog.Logger) Client {
	client, err := NewClient(cfg, logger)
	if err != nil {
		logger.Warn("failed to create LLM client, continuing without LLM support",
			"provider", cfg.Provider,
			"error", err,
		)
		return nil
	}
	return client
}

// ValidateConfig validates the LLM configuration.
func ValidateConfig(cfg Config) error {
	if cfg.Provider == "" {
		return nil // LLM is optional
	}

	switch cfg.Provider {
	case "openai":
		if cfg.OpenAI.APIKey == "" {
			return fmt.Errorf("openai api_key is required")
		}
		if cfg.Model == "" {
			return fmt.Errorf("model is required for openai")
		}
	case "anthropic":
		if cfg.Anthropic.APIKey == "" {
			return fmt.Errorf("anthropic api_key is required")
		}
		if cfg.Model == "" {
			return fmt.Errorf("model is required for anthropic")
		}
	case "ollama":
		// Ollama doesn't require API key, just endpoint
		if cfg.Model == "" {
			return fmt.Errorf("model is required for ollama")
		}
	default:
		return fmt.Errorf("unknown LLM provider: %s", cfg.Provider)
	}

	return nil
}
