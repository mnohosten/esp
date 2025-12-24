package llm

import (
	"context"
	"time"
)

// Client interface for LLM providers.
type Client interface {
	// Name returns the provider name.
	Name() string

	// Classify classifies text into categories.
	Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error)

	// Summarize generates a summary of text.
	Summarize(ctx context.Context, text string, maxLength int) (string, error)

	// Close cleans up resources.
	Close() error
}

// ClassifyRequest for classification.
type ClassifyRequest struct {
	Text       string
	Categories []Category
	Context    string // Optional additional context
}

// ClassifyResponse from classification.
type ClassifyResponse struct {
	Category   string         `json:"category"`
	Confidence float64        `json:"confidence"`
	Reasoning  string         `json:"reasoning"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Category definition.
type Category struct {
	Name        string   `json:"name" mapstructure:"name"`
	Description string   `json:"description" mapstructure:"description"`
	Examples    []string `json:"examples,omitempty" mapstructure:"examples"`
	Folder      string   `json:"folder,omitempty" mapstructure:"folder"` // Target mailbox folder
	Priority    int      `json:"priority,omitempty" mapstructure:"priority"`
}

// Config for LLM providers.
type Config struct {
	Provider string `mapstructure:"provider"` // openai, anthropic, ollama
	Model    string `mapstructure:"model"`

	// Provider-specific settings
	OpenAI    OpenAIConfig    `mapstructure:"openai"`
	Anthropic AnthropicConfig `mapstructure:"anthropic"`
	Ollama    OllamaConfig    `mapstructure:"ollama"`

	// Common settings
	Timeout     time.Duration `mapstructure:"timeout"`
	MaxTokens   int           `mapstructure:"max_tokens"`
	Temperature float64       `mapstructure:"temperature"`
}

// OpenAIConfig for OpenAI.
type OpenAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	OrgID   string `mapstructure:"org_id"`
	BaseURL string `mapstructure:"base_url"` // For Azure OpenAI or compatible APIs
}

// AnthropicConfig for Anthropic Claude.
type AnthropicConfig struct {
	APIKey string `mapstructure:"api_key"`
}

// OllamaConfig for local Ollama.
type OllamaConfig struct {
	Endpoint string `mapstructure:"endpoint"` // http://localhost:11434
}

// DefaultConfig returns the default LLM configuration.
func DefaultConfig() Config {
	return Config{
		Provider:    "ollama",
		Model:       "llama3.2",
		Timeout:     60 * time.Second,
		MaxTokens:   500,
		Temperature: 0.1,
		Ollama: OllamaConfig{
			Endpoint: "http://localhost:11434",
		},
	}
}

// DefaultCategories returns default email categories.
func DefaultCategories() []Category {
	return []Category{
		{
			Name:        "primary",
			Description: "Important personal or work emails that require attention or response",
			Folder:      "INBOX",
			Priority:    1,
		},
		{
			Name:        "social",
			Description: "Social network notifications, friend updates, social media alerts",
			Folder:      "Social",
			Priority:    2,
		},
		{
			Name:        "promotions",
			Description: "Marketing emails, deals, offers, newsletters, advertisements",
			Folder:      "Promotions",
			Priority:    3,
		},
		{
			Name:        "updates",
			Description: "Automated notifications, confirmations, receipts, statements",
			Folder:      "Updates",
			Priority:    4,
		},
		{
			Name:        "forums",
			Description: "Mailing lists, discussion groups, community forums",
			Folder:      "Forums",
			Priority:    5,
		},
	}
}
