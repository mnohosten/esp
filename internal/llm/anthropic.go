package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AnthropicClient implements Client for Anthropic Claude API.
type AnthropicClient struct {
	httpClient *http.Client
	model      string
	config     AnthropicConfig
	baseURL    string
	logger     *slog.Logger
}

// Anthropic API request/response types.
type anthropicRequest struct {
	Model       string                  `json:"model"`
	Messages    []anthropicMessage      `json:"messages"`
	System      string                  `json:"system,omitempty"`
	MaxTokens   int                     `json:"max_tokens"`
	Temperature float64                 `json:"temperature,omitempty"`
	Metadata    *anthropicMetadata      `json:"metadata,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

type anthropicResponse struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Role         string `json:"role"`
	Model        string `json:"model"`
	Content      []anthropicContentBlock `json:"content"`
	StopReason   string `json:"stop_reason"`
	StopSequence string `json:"stop_sequence,omitempty"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// NewAnthropic creates an Anthropic client.
func NewAnthropic(cfg Config, logger *slog.Logger) (*AnthropicClient, error) {
	if cfg.Anthropic.APIKey == "" {
		return nil, errors.New("anthropic api_key is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &AnthropicClient{
		httpClient: &http.Client{Timeout: timeout},
		model:      cfg.Model,
		config:     cfg.Anthropic,
		baseURL:    "https://api.anthropic.com/v1",
		logger:     logger,
	}, nil
}

// Name returns the provider name.
func (c *AnthropicClient) Name() string { return "anthropic" }

// Classify classifies text into categories.
func (c *AnthropicClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
	prompt := c.buildClassificationPrompt(req)

	anthropicReq := anthropicRequest{
		Model: c.model,
		Messages: []anthropicMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		System:      "You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only, no additional text.",
		MaxTokens:   500,
		Temperature: 0.1,
	}

	body, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if anthropicResp.Error != nil {
		return nil, fmt.Errorf("anthropic error: %s", anthropicResp.Error.Message)
	}

	// Extract text content
	var content string
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			content = block.Text
			break
		}
	}

	if content == "" {
		return nil, errors.New("no text content in response")
	}

	return c.parseResponse(content)
}

func (c *AnthropicClient) buildClassificationPrompt(req *ClassifyRequest) string {
	var sb strings.Builder

	sb.WriteString("Classify the following email into one of these categories:\n\n")

	for _, cat := range req.Categories {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", cat.Name, cat.Description))
		if len(cat.Examples) > 0 {
			sb.WriteString("  Examples: " + strings.Join(cat.Examples, ", ") + "\n")
		}
	}

	if req.Context != "" {
		sb.WriteString("\nAdditional context:\n")
		sb.WriteString(req.Context)
		sb.WriteString("\n")
	}

	sb.WriteString("\nEmail content:\n")
	sb.WriteString(req.Text)

	sb.WriteString("\n\nRespond with JSON in this format:\n")
	sb.WriteString(`{"category": "category_name", "confidence": 0.95, "reasoning": "brief explanation"}`)

	return sb.String()
}

func (c *AnthropicClient) parseResponse(content string) (*ClassifyResponse, error) {
	// Extract JSON from response (Claude might include extra text)
	content = strings.TrimSpace(content)
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response: %s", content)
	}

	jsonStr := content[start : end+1]

	var result struct {
		Category   string  `json:"category"`
		Confidence float64 `json:"confidence"`
		Reasoning  string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, content: %s", err, jsonStr)
	}

	return &ClassifyResponse{
		Category:   result.Category,
		Confidence: result.Confidence,
		Reasoning:  result.Reasoning,
	}, nil
}

// Summarize generates a summary of text.
func (c *AnthropicClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
	anthropicReq := anthropicRequest{
		Model: c.model,
		Messages: []anthropicMessage{
			{
				Role:    "user",
				Content: fmt.Sprintf("Please summarize this email in %d words or less. Be concise and capture the key points:\n\n%s", maxLength, text),
			},
		},
		System:      "You are a helpful assistant that creates concise email summaries.",
		MaxTokens:   maxLength * 2,
		Temperature: 0.3,
	}

	body, err := json.Marshal(anthropicReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if anthropicResp.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", anthropicResp.Error.Message)
	}

	// Extract text content
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			return strings.TrimSpace(block.Text), nil
		}
	}

	return "", errors.New("no text content in response")
}

// Close cleans up resources.
func (c *AnthropicClient) Close() error {
	return nil
}
