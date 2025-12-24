package llm

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mnohosten/esp/internal/filter"
	"github.com/mnohosten/esp/internal/llm"
)

// CategorizerFilter classifies emails using LLM.
type CategorizerFilter struct {
	client     llm.Client
	categories []llm.Category
	config     Config
	logger     *slog.Logger
}

// Config for the categorizer filter.
type Config struct {
	Enabled          bool           `mapstructure:"enabled"`
	MinConfidence    float64        `mapstructure:"min_confidence"`
	MaxContentLength int            `mapstructure:"max_content_length"`
	SkipSpam         bool           `mapstructure:"skip_spam"`
	Categories       []llm.Category `mapstructure:"categories"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:          false,
		MinConfidence:    0.7,
		MaxContentLength: 4000,
		SkipSpam:         true,
		Categories:       llm.DefaultCategories(),
	}
}

// NewCategorizerFilter creates a categorization filter.
func NewCategorizerFilter(client llm.Client, cfg Config, logger *slog.Logger) *CategorizerFilter {
	if len(cfg.Categories) == 0 {
		cfg.Categories = llm.DefaultCategories()
	}

	if cfg.MaxContentLength == 0 {
		cfg.MaxContentLength = 4000
	}

	if cfg.MinConfidence == 0 {
		cfg.MinConfidence = 0.7
	}

	return &CategorizerFilter{
		client:     client,
		categories: cfg.Categories,
		config:     cfg,
		logger:     logger,
	}
}

// Name returns the filter name.
func (f *CategorizerFilter) Name() string { return "llm-categorizer" }

// Priority returns execution order (run late in pipeline, after spam/virus checks).
func (f *CategorizerFilter) Priority() int { return 500 }

// Process classifies the message using LLM.
func (f *CategorizerFilter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
	result := filter.NewResult()

	if !f.config.Enabled {
		return result, nil
	}

	if f.client == nil {
		f.logger.Debug("llm client not configured, skipping categorization")
		return result, nil
	}

	// Check if message is already tagged as spam
	if f.config.SkipSpam && f.isSpam(msg) {
		f.logger.Debug("skipping spam message for categorization",
			"from", msg.From,
			"subject", msg.Subject,
		)
		return result, nil
	}

	// Extract content for classification
	content := f.extractContent(msg)
	if len(content) > f.config.MaxContentLength {
		content = content[:f.config.MaxContentLength]
	}

	// Skip very short emails
	if len(content) < 50 {
		f.logger.Debug("skipping short message for categorization",
			"from", msg.From,
			"length", len(content),
		)
		return result, nil
	}

	// Classify using LLM
	resp, err := f.client.Classify(ctx, &llm.ClassifyRequest{
		Text:       content,
		Categories: f.categories,
	})
	if err != nil {
		f.logger.Error("llm classification failed",
			"from", msg.From,
			"subject", msg.Subject,
			"error", err,
		)
		// Fail open - don't block delivery on LLM errors
		return result, nil
	}

	f.logger.Debug("llm classification complete",
		"from", msg.From,
		"subject", msg.Subject,
		"category", resp.Category,
		"confidence", resp.Confidence,
	)

	// Add classification headers
	result.Headers["X-LLM-Category"] = resp.Category
	result.Headers["X-LLM-Confidence"] = fmt.Sprintf("%.2f", resp.Confidence)
	result.Headers["X-LLM-Provider"] = f.client.Name()

	// Add metadata
	result.Metadata["llm_category"] = resp.Category
	result.Metadata["llm_confidence"] = resp.Confidence
	result.Metadata["llm_reasoning"] = resp.Reasoning
	result.Metadata["llm_provider"] = f.client.Name()

	// Add tag for the category
	result.Tags = append(result.Tags, "llm:"+resp.Category)

	// Set target folder if confidence is high enough
	if resp.Confidence >= f.config.MinConfidence {
		for _, cat := range f.categories {
			if strings.EqualFold(cat.Name, resp.Category) && cat.Folder != "" {
				result.TargetFolder = cat.Folder
				f.logger.Debug("setting target folder from llm",
					"category", resp.Category,
					"folder", cat.Folder,
				)
				break
			}
		}
	}

	return result, nil
}

// extractContent extracts email content for classification.
func (f *CategorizerFilter) extractContent(msg *filter.Message) string {
	var sb strings.Builder

	// Add subject
	sb.WriteString("Subject: ")
	sb.WriteString(msg.Subject)
	sb.WriteString("\n\n")

	// Add from
	sb.WriteString("From: ")
	sb.WriteString(msg.From)
	sb.WriteString("\n\n")

	// Add body
	sb.WriteString("Body:\n")
	sb.Write(msg.Body)

	return sb.String()
}

// isSpam checks if the message has spam indicators.
func (f *CategorizerFilter) isSpam(msg *filter.Message) bool {
	// Check headers for spam indicators
	if spamStatus, ok := msg.Headers["X-Spam-Status"]; ok {
		for _, v := range spamStatus {
			if strings.Contains(strings.ToLower(v), "yes") {
				return true
			}
		}
	}

	if spamFlag, ok := msg.Headers["X-Spam-Flag"]; ok {
		for _, v := range spamFlag {
			if strings.ToLower(v) == "yes" {
				return true
			}
		}
	}

	return false
}

// UpdateCategories updates the category list.
func (f *CategorizerFilter) UpdateCategories(categories []llm.Category) {
	f.categories = categories
}

// Close cleans up resources.
func (f *CategorizerFilter) Close() error {
	if f.client != nil {
		return f.client.Close()
	}
	return nil
}

// Ensure CategorizerFilter implements filter.Filter
var _ filter.Filter = (*CategorizerFilter)(nil)
