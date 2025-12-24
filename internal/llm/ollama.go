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

// OllamaClient implements Client for local Ollama.
type OllamaClient struct {
	httpClient *http.Client
	endpoint   string
	model      string
	logger     *slog.Logger
}

// Ollama API request/response types.
type ollamaGenerateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	System  string         `json:"system,omitempty"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format,omitempty"` // "json"
	Options map[string]any `json:"options,omitempty"`
}

type ollamaGenerateResponse struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	Context            []int  `json:"context,omitempty"`
	TotalDuration      int64  `json:"total_duration,omitempty"`
	LoadDuration       int64  `json:"load_duration,omitempty"`
	PromptEvalCount    int    `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64  `json:"prompt_eval_duration,omitempty"`
	EvalCount          int    `json:"eval_count,omitempty"`
	EvalDuration       int64  `json:"eval_duration,omitempty"`
}

type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Format   string              `json:"format,omitempty"` // "json"
	Options  map[string]any      `json:"options,omitempty"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatResponse struct {
	Model     string            `json:"model"`
	CreatedAt string            `json:"created_at"`
	Message   ollamaChatMessage `json:"message"`
	Done      bool              `json:"done"`
}

// NewOllama creates an Ollama client.
func NewOllama(cfg Config, logger *slog.Logger) (*OllamaClient, error) {
	endpoint := cfg.Ollama.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 120 * time.Second // Longer timeout for local models
	}

	model := cfg.Model
	if model == "" {
		model = "llama3.2"
	}

	return &OllamaClient{
		httpClient: &http.Client{Timeout: timeout},
		endpoint:   endpoint,
		model:      model,
		logger:     logger,
	}, nil
}

// Name returns the provider name.
func (c *OllamaClient) Name() string { return "ollama" }

// Classify classifies text into categories.
func (c *OllamaClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
	prompt := c.buildClassificationPrompt(req)

	// Use chat API for better instruction following
	chatReq := ollamaChatRequest{
		Model: c.model,
		Messages: []ollamaChatMessage{
			{
				Role:    "system",
				Content: "You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only, no additional text or explanation outside the JSON object.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": 0.1,
			"num_predict": 500,
		},
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp ollamaChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResponse(chatResp.Message.Content)
}

func (c *OllamaClient) buildClassificationPrompt(req *ClassifyRequest) string {
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

	sb.WriteString("\n\nRespond with only this JSON format, no other text:\n")
	sb.WriteString(`{"category": "category_name", "confidence": 0.95, "reasoning": "brief explanation"}`)

	return sb.String()
}

func (c *OllamaClient) parseResponse(content string) (*ClassifyResponse, error) {
	// Clean up the response
	content = strings.TrimSpace(content)

	// Extract JSON from response
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start != -1 && end != -1 && end > start {
		content = content[start : end+1]
	}

	var result struct {
		Category   string  `json:"category"`
		Confidence float64 `json:"confidence"`
		Reasoning  string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, content: %s", err, content)
	}

	// Ensure confidence is in valid range
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}

	return &ClassifyResponse{
		Category:   result.Category,
		Confidence: result.Confidence,
		Reasoning:  result.Reasoning,
	}, nil
}

// Summarize generates a summary of text.
func (c *OllamaClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
	chatReq := ollamaChatRequest{
		Model: c.model,
		Messages: []ollamaChatMessage{
			{
				Role:    "system",
				Content: "You are a helpful assistant that creates concise email summaries. Respond with only the summary text, no additional commentary.",
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Please summarize this email in %d words or less. Be concise and capture the key points:\n\n%s", maxLength, text),
			},
		},
		Stream: false,
		Options: map[string]any{
			"temperature": 0.3,
			"num_predict": maxLength * 3,
		},
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp ollamaChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return strings.TrimSpace(chatResp.Message.Content), nil
}

// Ping checks if the Ollama server is available.
func (c *OllamaClient) Ping(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.endpoint+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned %d", resp.StatusCode)
	}

	return nil
}

// ListModels returns available models.
func (c *OllamaClient) ListModels(ctx context.Context) ([]string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.endpoint+"/api/tags", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned %d", resp.StatusCode)
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	models := make([]string, len(result.Models))
	for i, m := range result.Models {
		models[i] = m.Name
	}

	return models, nil
}

// PullModel pulls a model if not already available.
func (c *OllamaClient) PullModel(ctx context.Context, model string) error {
	pullReq := struct {
		Name   string `json:"name"`
		Stream bool   `json:"stream"`
	}{
		Name:   model,
		Stream: false,
	}

	body, err := json.Marshal(pullReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/pull", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Close cleans up resources.
func (c *OllamaClient) Close() error {
	return nil
}

// IsAvailable checks if Ollama is available and has the model.
func (c *OllamaClient) IsAvailable(ctx context.Context) bool {
	if err := c.Ping(ctx); err != nil {
		return false
	}

	models, err := c.ListModels(ctx)
	if err != nil {
		return false
	}

	for _, m := range models {
		if m == c.model || strings.HasPrefix(m, c.model+":") {
			return true
		}
	}

	return false
}

// EnsureModel ensures the model is available, pulling it if necessary.
func (c *OllamaClient) EnsureModel(ctx context.Context) error {
	if c.IsAvailable(ctx) {
		return nil
	}

	c.logger.Info("pulling ollama model", "model", c.model)
	if err := c.PullModel(ctx, c.model); err != nil {
		return fmt.Errorf("failed to pull model %s: %w", c.model, err)
	}

	return nil
}

// NewOllamaWithCheck creates an Ollama client and verifies connectivity.
func NewOllamaWithCheck(cfg Config, logger *slog.Logger) (*OllamaClient, error) {
	client, err := NewOllama(cfg, logger)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		return nil, errors.New("ollama is not available - please ensure ollama is running")
	}

	return client, nil
}
