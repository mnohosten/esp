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

// OpenAIClient implements Client for OpenAI API.
type OpenAIClient struct {
	httpClient *http.Client
	model      string
	config     OpenAIConfig
	baseURL    string
	logger     *slog.Logger
}

// OpenAI API request/response types.
type openAIChatRequest struct {
	Model          string              `json:"model"`
	Messages       []openAIChatMessage `json:"messages"`
	Temperature    float64             `json:"temperature,omitempty"`
	MaxTokens      int                 `json:"max_tokens,omitempty"`
	ResponseFormat *openAIRespFormat   `json:"response_format,omitempty"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRespFormat struct {
	Type string `json:"type"`
}

type openAIChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// NewOpenAI creates an OpenAI client.
func NewOpenAI(cfg Config, logger *slog.Logger) (*OpenAIClient, error) {
	if cfg.OpenAI.APIKey == "" {
		return nil, errors.New("openai api_key is required")
	}

	baseURL := cfg.OpenAI.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &OpenAIClient{
		httpClient: &http.Client{Timeout: timeout},
		model:      cfg.Model,
		config:     cfg.OpenAI,
		baseURL:    baseURL,
		logger:     logger,
	}, nil
}

// Name returns the provider name.
func (c *OpenAIClient) Name() string { return "openai" }

// Classify classifies text into categories.
func (c *OpenAIClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
	prompt := c.buildClassificationPrompt(req)

	chatReq := openAIChatRequest{
		Model: c.model,
		Messages: []openAIChatMessage{
			{
				Role:    "system",
				Content: "You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Temperature: 0.1,
		MaxTokens:   500,
		ResponseFormat: &openAIRespFormat{
			Type: "json_object",
		},
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	if c.config.OrgID != "" {
		httpReq.Header.Set("OpenAI-Organization", c.config.OrgID)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if chatResp.Error != nil {
		return nil, fmt.Errorf("openai error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, errors.New("no response from OpenAI")
	}

	return c.parseResponse(chatResp.Choices[0].Message.Content)
}

func (c *OpenAIClient) buildClassificationPrompt(req *ClassifyRequest) string {
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

func (c *OpenAIClient) parseResponse(content string) (*ClassifyResponse, error) {
	// Extract JSON from response (in case of extra text)
	content = strings.TrimSpace(content)
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

	return &ClassifyResponse{
		Category:   result.Category,
		Confidence: result.Confidence,
		Reasoning:  result.Reasoning,
	}, nil
}

// Summarize generates a summary of text.
func (c *OpenAIClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
	chatReq := openAIChatRequest{
		Model: c.model,
		Messages: []openAIChatMessage{
			{
				Role:    "system",
				Content: fmt.Sprintf("Summarize the following email in %d words or less. Be concise and capture the key points.", maxLength),
			},
			{
				Role:    "user",
				Content: text,
			},
		},
		Temperature: 0.3,
		MaxTokens:   maxLength * 2,
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	if c.config.OrgID != "" {
		httpReq.Header.Set("OpenAI-Organization", c.config.OrgID)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("openai error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", errors.New("no response from OpenAI")
	}

	return strings.TrimSpace(chatResp.Choices[0].Message.Content), nil
}

// Close cleans up resources.
func (c *OpenAIClient) Close() error {
	return nil
}
