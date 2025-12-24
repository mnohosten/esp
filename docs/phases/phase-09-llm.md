# Phase 9: LLM Integration

## Overview

**Goal**: Implement email categorization using multiple LLM providers (OpenAI, Anthropic Claude, Ollama).

**Dependencies**: Phase 5 (Filter Pipeline)

**Estimated Complexity**: Medium

## Prerequisites

- Phase 5 completed
- API keys for cloud providers (OpenAI, Anthropic)
- Ollama installed for local models (optional)

## Deliverables

1. LLM client interface
2. OpenAI implementation
3. Anthropic Claude implementation
4. Ollama implementation
5. Categorization filter
6. Category configuration
7. Confidence scoring

## Core Components

### 1. LLM Client Interface

**File**: `internal/llm/client.go`

```go
// Client interface for LLM providers
type Client interface {
    // Name returns the provider name
    Name() string

    // Classify classifies text into categories
    Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error)

    // Summarize generates a summary of text
    Summarize(ctx context.Context, text string, maxLength int) (string, error)

    // Close cleans up resources
    Close() error
}

// ClassifyRequest for classification
type ClassifyRequest struct {
    Text       string
    Categories []Category
    Context    string // Optional additional context
}

// ClassifyResponse from classification
type ClassifyResponse struct {
    Category   string
    Confidence float64
    Reasoning  string
    Metadata   map[string]any
}

// Category definition
type Category struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Examples    []string `json:"examples,omitempty"`
    Folder      string `json:"folder,omitempty"` // Target mailbox folder
    Priority    int    `json:"priority,omitempty"`
}

// Config for LLM providers
type Config struct {
    Provider    string `mapstructure:"provider"` // openai, anthropic, ollama
    Model       string `mapstructure:"model"`

    // Provider-specific settings
    OpenAI    OpenAIConfig    `mapstructure:"openai"`
    Anthropic AnthropicConfig `mapstructure:"anthropic"`
    Ollama    OllamaConfig    `mapstructure:"ollama"`

    // Common settings
    Timeout     time.Duration `mapstructure:"timeout"`
    MaxTokens   int           `mapstructure:"max_tokens"`
    Temperature float64       `mapstructure:"temperature"`
}
```

### 2. OpenAI Client

**File**: `internal/llm/openai.go`

```go
// OpenAIClient implements Client for OpenAI API
type OpenAIClient struct {
    client *openai.Client
    model  string
    config OpenAIConfig
    logger *slog.Logger
}

// OpenAIConfig for OpenAI
type OpenAIConfig struct {
    APIKey  string `mapstructure:"api_key"`
    OrgID   string `mapstructure:"org_id"`
    BaseURL string `mapstructure:"base_url"` // For Azure OpenAI
}

// NewOpenAI creates an OpenAI client
func NewOpenAI(cfg Config, logger *slog.Logger) (*OpenAIClient, error) {
    config := openai.DefaultConfig(cfg.OpenAI.APIKey)
    if cfg.OpenAI.OrgID != "" {
        config.OrgID = cfg.OpenAI.OrgID
    }
    if cfg.OpenAI.BaseURL != "" {
        config.BaseURL = cfg.OpenAI.BaseURL
    }

    return &OpenAIClient{
        client: openai.NewClientWithConfig(config),
        model:  cfg.Model,
        config: cfg.OpenAI,
        logger: logger,
    }, nil
}

func (c *OpenAIClient) Name() string { return "openai" }

func (c *OpenAIClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
    prompt := c.buildClassificationPrompt(req)

    resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
        Model: c.model,
        Messages: []openai.ChatCompletionMessage{
            {
                Role:    openai.ChatMessageRoleSystem,
                Content: "You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only.",
            },
            {
                Role:    openai.ChatMessageRoleUser,
                Content: prompt,
            },
        },
        ResponseFormat: &openai.ChatCompletionResponseFormat{
            Type: openai.ChatCompletionResponseFormatTypeJSONObject,
        },
        Temperature: 0.1,
        MaxTokens:   500,
    })

    if err != nil {
        return nil, fmt.Errorf("openai request failed: %w", err)
    }

    if len(resp.Choices) == 0 {
        return nil, errors.New("no response from OpenAI")
    }

    return c.parseResponse(resp.Choices[0].Message.Content)
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

    sb.WriteString("\nEmail content:\n")
    sb.WriteString(req.Text)

    sb.WriteString("\n\nRespond with JSON in this format:\n")
    sb.WriteString(`{"category": "category_name", "confidence": 0.95, "reasoning": "brief explanation"}`)

    return sb.String()
}

func (c *OpenAIClient) parseResponse(content string) (*ClassifyResponse, error) {
    var result struct {
        Category   string  `json:"category"`
        Confidence float64 `json:"confidence"`
        Reasoning  string  `json:"reasoning"`
    }

    if err := json.Unmarshal([]byte(content), &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    return &ClassifyResponse{
        Category:   result.Category,
        Confidence: result.Confidence,
        Reasoning:  result.Reasoning,
    }, nil
}

func (c *OpenAIClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
    resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
        Model: c.model,
        Messages: []openai.ChatCompletionMessage{
            {
                Role:    openai.ChatMessageRoleSystem,
                Content: fmt.Sprintf("Summarize the following email in %d words or less.", maxLength),
            },
            {
                Role:    openai.ChatMessageRoleUser,
                Content: text,
            },
        },
        Temperature: 0.3,
        MaxTokens:   maxLength * 2, // Rough estimate
    })

    if err != nil {
        return "", fmt.Errorf("openai request failed: %w", err)
    }

    if len(resp.Choices) == 0 {
        return "", errors.New("no response from OpenAI")
    }

    return resp.Choices[0].Message.Content, nil
}

func (c *OpenAIClient) Close() error {
    return nil
}
```

### 3. Anthropic Client

**File**: `internal/llm/anthropic.go`

```go
// AnthropicClient implements Client for Anthropic Claude API
type AnthropicClient struct {
    client *anthropic.Client
    model  string
    config AnthropicConfig
    logger *slog.Logger
}

// AnthropicConfig for Anthropic
type AnthropicConfig struct {
    APIKey string `mapstructure:"api_key"`
}

// NewAnthropic creates an Anthropic client
func NewAnthropic(cfg Config, logger *slog.Logger) (*AnthropicClient, error) {
    client := anthropic.NewClient(cfg.Anthropic.APIKey)

    return &AnthropicClient{
        client: client,
        model:  cfg.Model,
        config: cfg.Anthropic,
        logger: logger,
    }, nil
}

func (c *AnthropicClient) Name() string { return "anthropic" }

func (c *AnthropicClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
    prompt := c.buildClassificationPrompt(req)

    resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
        Model:     anthropic.F(c.model),
        MaxTokens: anthropic.F(int64(500)),
        Messages: anthropic.F([]anthropic.MessageParam{
            anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
        }),
        System: anthropic.F([]anthropic.TextBlockParam{
            anthropic.NewTextBlock("You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only."),
        }),
    })

    if err != nil {
        return nil, fmt.Errorf("anthropic request failed: %w", err)
    }

    // Extract text content
    var content string
    for _, block := range resp.Content {
        if block.Type == anthropic.ContentBlockTypeText {
            content = block.Text
            break
        }
    }

    return c.parseResponse(content)
}

func (c *AnthropicClient) buildClassificationPrompt(req *ClassifyRequest) string {
    // Similar to OpenAI implementation
    var sb strings.Builder

    sb.WriteString("Classify the following email into one of these categories:\n\n")

    for _, cat := range req.Categories {
        sb.WriteString(fmt.Sprintf("- %s: %s\n", cat.Name, cat.Description))
    }

    sb.WriteString("\nEmail content:\n")
    sb.WriteString(req.Text)

    sb.WriteString("\n\nRespond with JSON in this format:\n")
    sb.WriteString(`{"category": "category_name", "confidence": 0.95, "reasoning": "brief explanation"}`)

    return sb.String()
}

func (c *AnthropicClient) parseResponse(content string) (*ClassifyResponse, error) {
    // Extract JSON from response (Claude might include extra text)
    start := strings.Index(content, "{")
    end := strings.LastIndex(content, "}")
    if start == -1 || end == -1 {
        return nil, errors.New("no JSON found in response")
    }

    jsonStr := content[start : end+1]

    var result struct {
        Category   string  `json:"category"`
        Confidence float64 `json:"confidence"`
        Reasoning  string  `json:"reasoning"`
    }

    if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    return &ClassifyResponse{
        Category:   result.Category,
        Confidence: result.Confidence,
        Reasoning:  result.Reasoning,
    }, nil
}

func (c *AnthropicClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
    // Similar implementation
    return "", nil
}

func (c *AnthropicClient) Close() error {
    return nil
}
```

### 4. Ollama Client

**File**: `internal/llm/ollama.go`

```go
// OllamaClient implements Client for local Ollama
type OllamaClient struct {
    endpoint string
    model    string
    client   *http.Client
    logger   *slog.Logger
}

// OllamaConfig for Ollama
type OllamaConfig struct {
    Endpoint string `mapstructure:"endpoint"` // http://localhost:11434
}

// NewOllama creates an Ollama client
func NewOllama(cfg Config, logger *slog.Logger) (*OllamaClient, error) {
    endpoint := cfg.Ollama.Endpoint
    if endpoint == "" {
        endpoint = "http://localhost:11434"
    }

    return &OllamaClient{
        endpoint: endpoint,
        model:    cfg.Model,
        client:   &http.Client{Timeout: cfg.Timeout},
        logger:   logger,
    }, nil
}

func (c *OllamaClient) Name() string { return "ollama" }

// OllamaRequest for API calls
type OllamaRequest struct {
    Model    string `json:"model"`
    Prompt   string `json:"prompt"`
    System   string `json:"system,omitempty"`
    Stream   bool   `json:"stream"`
    Format   string `json:"format,omitempty"` // "json"
    Options  map[string]any `json:"options,omitempty"`
}

// OllamaResponse from API
type OllamaResponse struct {
    Response string `json:"response"`
    Done     bool   `json:"done"`
}

func (c *OllamaClient) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, error) {
    prompt := c.buildClassificationPrompt(req)

    ollamaReq := OllamaRequest{
        Model:  c.model,
        Prompt: prompt,
        System: "You are an email classification assistant. Classify the email into exactly one of the provided categories. Respond with JSON only.",
        Stream: false,
        Format: "json",
        Options: map[string]any{
            "temperature": 0.1,
        },
    }

    body, err := json.Marshal(ollamaReq)
    if err != nil {
        return nil, err
    }

    httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/generate", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := c.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("ollama request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        respBody, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(respBody))
    }

    var ollamaResp OllamaResponse
    if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return c.parseResponse(ollamaResp.Response)
}

func (c *OllamaClient) buildClassificationPrompt(req *ClassifyRequest) string {
    // Similar to other implementations
    var sb strings.Builder

    sb.WriteString("Classify the following email into one of these categories:\n\n")

    for _, cat := range req.Categories {
        sb.WriteString(fmt.Sprintf("- %s: %s\n", cat.Name, cat.Description))
    }

    sb.WriteString("\nEmail content:\n")
    sb.WriteString(req.Text)

    sb.WriteString("\n\nRespond with JSON: {\"category\": \"name\", \"confidence\": 0.95, \"reasoning\": \"why\"}")

    return sb.String()
}

func (c *OllamaClient) parseResponse(content string) (*ClassifyResponse, error) {
    var result struct {
        Category   string  `json:"category"`
        Confidence float64 `json:"confidence"`
        Reasoning  string  `json:"reasoning"`
    }

    if err := json.Unmarshal([]byte(content), &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    return &ClassifyResponse{
        Category:   result.Category,
        Confidence: result.Confidence,
        Reasoning:  result.Reasoning,
    }, nil
}

func (c *OllamaClient) Summarize(ctx context.Context, text string, maxLength int) (string, error) {
    // Implementation similar to Classify
    return "", nil
}

func (c *OllamaClient) Close() error {
    return nil
}
```

### 5. Categorization Filter

**File**: `internal/filter/llm/categorizer.go`

```go
// CategorizerFilter classifies emails using LLM
type CategorizerFilter struct {
    client     llm.Client
    categories []llm.Category
    config     CategorizerConfig
    logger     *slog.Logger
}

// CategorizerConfig for the filter
type CategorizerConfig struct {
    Enabled           bool          `mapstructure:"enabled"`
    MinConfidence     float64       `mapstructure:"min_confidence"`
    MaxContentLength  int           `mapstructure:"max_content_length"`
    SkipSpam          bool          `mapstructure:"skip_spam"`
    Categories        []llm.Category `mapstructure:"categories"`
}

// NewCategorizerFilter creates a categorization filter
func NewCategorizerFilter(client llm.Client, cfg CategorizerConfig, logger *slog.Logger) *CategorizerFilter {
    // Default categories if none configured
    if len(cfg.Categories) == 0 {
        cfg.Categories = DefaultCategories()
    }

    return &CategorizerFilter{
        client:     client,
        categories: cfg.Categories,
        config:     cfg,
        logger:     logger,
    }
}

func (f *CategorizerFilter) Name() string { return "llm-categorizer" }
func (f *CategorizerFilter) Priority() int { return 500 } // Run late in pipeline

func (f *CategorizerFilter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
    if !f.config.Enabled {
        return &filter.Result{Action: filter.ActionAccept}, nil
    }

    // Skip if already marked as spam
    if f.config.SkipSpam && msg.IsSpam {
        return &filter.Result{Action: filter.ActionAccept}, nil
    }

    // Extract content for classification
    content := f.extractContent(msg)
    if len(content) > f.config.MaxContentLength {
        content = content[:f.config.MaxContentLength]
    }

    // Classify
    resp, err := f.client.Classify(ctx, &llm.ClassifyRequest{
        Text:       content,
        Categories: f.categories,
    })
    if err != nil {
        f.logger.Error("llm classification failed", "error", err)
        // Fail open - don't block delivery on LLM errors
        return &filter.Result{Action: filter.ActionAccept}, nil
    }

    result := &filter.Result{
        Action: filter.ActionAccept,
        Headers: map[string]string{
            "X-LLM-Category":   resp.Category,
            "X-LLM-Confidence": fmt.Sprintf("%.2f", resp.Confidence),
        },
        Metadata: map[string]any{
            "llm_category":   resp.Category,
            "llm_confidence": resp.Confidence,
            "llm_reasoning":  resp.Reasoning,
            "llm_provider":   f.client.Name(),
        },
    }

    // Set target folder if confidence is high enough
    if resp.Confidence >= f.config.MinConfidence {
        for _, cat := range f.categories {
            if cat.Name == resp.Category && cat.Folder != "" {
                result.TargetFolder = cat.Folder
                break
            }
        }
    }

    return result, nil
}

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

    // Add body (first part)
    sb.WriteString("Body:\n")
    sb.Write(msg.Body)

    return sb.String()
}

// DefaultCategories returns default email categories
func DefaultCategories() []llm.Category {
    return []llm.Category{
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
```

### 6. LLM Factory

**File**: `internal/llm/factory.go`

```go
// NewClient creates an LLM client based on configuration
func NewClient(cfg Config, logger *slog.Logger) (Client, error) {
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
```

## Task Breakdown

### Client Interface
- [ ] Define Client interface
- [ ] Define request/response types
- [ ] Define category structure

### OpenAI Implementation
- [ ] Implement OpenAI client
- [ ] Build classification prompt
- [ ] Parse JSON response
- [ ] Handle errors gracefully

### Anthropic Implementation
- [ ] Implement Anthropic client
- [ ] Adapt prompts for Claude
- [ ] Parse responses
- [ ] Handle API specifics

### Ollama Implementation
- [ ] Implement Ollama HTTP client
- [ ] Support local models
- [ ] Handle streaming responses
- [ ] Test with various models

### Categorization Filter
- [ ] Create filter implementation
- [ ] Extract email content
- [ ] Handle classification results
- [ ] Set target folders
- [ ] Add X-LLM-* headers

### Configuration
- [ ] Provider selection
- [ ] Model configuration
- [ ] Category customization
- [ ] Confidence thresholds

## Configuration

```yaml
filters:
  llm:
    enabled: true
    provider: "openai"  # openai, anthropic, ollama
    model: "gpt-4o-mini"  # or claude-3-haiku, llama3.2

    # Minimum confidence to apply category
    min_confidence: 0.7

    # Maximum content to send to LLM
    max_content_length: 4000

    # Skip already-spam emails
    skip_spam: true

    # Provider settings
    openai:
      api_key: "sk-..."

    anthropic:
      api_key: "sk-ant-..."

    ollama:
      endpoint: "http://localhost:11434"

    # Custom categories (optional, overrides defaults)
    categories:
      - name: "primary"
        description: "Important emails requiring attention"
        folder: "INBOX"
        priority: 1
      - name: "receipts"
        description: "Purchase receipts and order confirmations"
        folder: "Receipts"
        priority: 2
      # ... more categories
```

## Testing

### Unit Tests
- Prompt building
- Response parsing
- Filter logic

### Integration Tests
- OpenAI API (with real key)
- Anthropic API (with real key)
- Ollama (with local model)

### Test with Sample Emails
```bash
# Create test emails
echo "Subject: Meeting tomorrow
From: boss@company.com

Can we meet at 3pm to discuss the Q4 budget?" | ./test-classify

echo "Subject: 50% OFF EVERYTHING!
From: deals@store.com

Limited time offer! Shop now!" | ./test-classify
```

## Completion Criteria

- [ ] OpenAI client works
- [ ] Anthropic client works
- [ ] Ollama client works
- [ ] Classification filter processes emails
- [ ] Categories configurable
- [ ] Headers added to messages
- [ ] Target folders set correctly
- [ ] Graceful error handling
- [ ] All tests pass

## Next Phase

Once Phase 9 is complete, proceed to [Phase 10: Production Readiness](./phase-10-production.md).
