package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultCategories(t *testing.T) {
	categories := DefaultCategories()

	if len(categories) == 0 {
		t.Fatal("expected default categories")
	}

	// Check that all categories have required fields
	for _, cat := range categories {
		if cat.Name == "" {
			t.Error("category missing name")
		}
		if cat.Description == "" {
			t.Errorf("category %s missing description", cat.Name)
		}
		if cat.Folder == "" {
			t.Errorf("category %s missing folder", cat.Name)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Provider != "ollama" {
		t.Errorf("expected default provider ollama, got %s", cfg.Provider)
	}
	if cfg.Model != "llama3.2" {
		t.Errorf("expected default model llama3.2, got %s", cfg.Model)
	}
	if cfg.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty config is valid",
			cfg:     Config{},
			wantErr: false,
		},
		{
			name: "openai missing api key",
			cfg: Config{
				Provider: "openai",
				Model:    "gpt-4",
			},
			wantErr: true,
		},
		{
			name: "openai valid",
			cfg: Config{
				Provider: "openai",
				Model:    "gpt-4",
				OpenAI:   OpenAIConfig{APIKey: "sk-test"},
			},
			wantErr: false,
		},
		{
			name: "anthropic missing api key",
			cfg: Config{
				Provider: "anthropic",
				Model:    "claude-3-haiku",
			},
			wantErr: true,
		},
		{
			name: "anthropic valid",
			cfg: Config{
				Provider:  "anthropic",
				Model:     "claude-3-haiku",
				Anthropic: AnthropicConfig{APIKey: "sk-ant-test"},
			},
			wantErr: false,
		},
		{
			name: "ollama valid",
			cfg: Config{
				Provider: "ollama",
				Model:    "llama3.2",
			},
			wantErr: false,
		},
		{
			name: "unknown provider",
			cfg: Config{
				Provider: "unknown",
				Model:    "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOpenAIClassify(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Check headers
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected authorization header")
		}

		// Return mock response
		resp := map[string]any{
			"id":     "test-id",
			"object": "chat.completion",
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"role":    "assistant",
						"content": `{"category": "primary", "confidence": 0.95, "reasoning": "test"}`,
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		Provider: "openai",
		Model:    "gpt-4",
		OpenAI: OpenAIConfig{
			APIKey:  "test-key",
			BaseURL: server.URL,
		},
	}

	client, err := NewOpenAI(cfg, nil)
	if err != nil {
		t.Fatalf("NewOpenAI failed: %v", err)
	}

	resp, err := client.Classify(context.Background(), &ClassifyRequest{
		Text:       "Test email content",
		Categories: DefaultCategories(),
	})
	if err != nil {
		t.Fatalf("Classify failed: %v", err)
	}

	if resp.Category != "primary" {
		t.Errorf("expected category primary, got %s", resp.Category)
	}
	if resp.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", resp.Confidence)
	}
}

func TestAnthropicClassify(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Check headers
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("unexpected api key header")
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing anthropic-version header")
		}

		// Return mock response
		resp := map[string]any{
			"id":   "test-id",
			"type": "message",
			"role": "assistant",
			"content": []map[string]any{
				{
					"type": "text",
					"text": `{"category": "promotions", "confidence": 0.88, "reasoning": "marketing email"}`,
				},
			},
			"stop_reason": "end_turn",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &AnthropicClient{
		httpClient: http.DefaultClient,
		model:      "claude-3-haiku",
		config:     AnthropicConfig{APIKey: "test-key"},
		baseURL:    server.URL,
		logger:     nil,
	}

	resp, err := client.Classify(context.Background(), &ClassifyRequest{
		Text:       "50% OFF EVERYTHING!",
		Categories: DefaultCategories(),
	})
	if err != nil {
		t.Fatalf("Classify failed: %v", err)
	}

	if resp.Category != "promotions" {
		t.Errorf("expected category promotions, got %s", resp.Category)
	}
	if resp.Confidence != 0.88 {
		t.Errorf("expected confidence 0.88, got %f", resp.Confidence)
	}
}

func TestOllamaClassify(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Return mock response
		resp := map[string]any{
			"model":      "llama3.2",
			"created_at": "2024-01-01T00:00:00Z",
			"message": map[string]string{
				"role":    "assistant",
				"content": `{"category": "updates", "confidence": 0.92, "reasoning": "notification email"}`,
			},
			"done": true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		Provider: "ollama",
		Model:    "llama3.2",
		Ollama:   OllamaConfig{Endpoint: server.URL},
	}

	client, err := NewOllama(cfg, nil)
	if err != nil {
		t.Fatalf("NewOllama failed: %v", err)
	}

	resp, err := client.Classify(context.Background(), &ClassifyRequest{
		Text:       "Your order has shipped!",
		Categories: DefaultCategories(),
	})
	if err != nil {
		t.Fatalf("Classify failed: %v", err)
	}

	if resp.Category != "updates" {
		t.Errorf("expected category updates, got %s", resp.Category)
	}
	if resp.Confidence != 0.92 {
		t.Errorf("expected confidence 0.92, got %f", resp.Confidence)
	}
}

func TestParseResponseWithExtraText(t *testing.T) {
	client := &OpenAIClient{}

	tests := []struct {
		name     string
		content  string
		wantCat  string
		wantConf float64
		wantErr  bool
	}{
		{
			name:     "pure json",
			content:  `{"category": "primary", "confidence": 0.9, "reasoning": "test"}`,
			wantCat:  "primary",
			wantConf: 0.9,
		},
		{
			name:     "json with surrounding text",
			content:  `Here's the classification: {"category": "social", "confidence": 0.85, "reasoning": "social media"} Done.`,
			wantCat:  "social",
			wantConf: 0.85,
		},
		{
			name:     "json with newlines",
			content:  "\n\n{\"category\": \"updates\", \"confidence\": 0.8, \"reasoning\": \"receipt\"}\n\n",
			wantCat:  "updates",
			wantConf: 0.8,
		},
		{
			name:    "no json",
			content: "This is not valid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.parseResponse(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if resp.Category != tt.wantCat {
				t.Errorf("category = %v, want %v", resp.Category, tt.wantCat)
			}
			if resp.Confidence != tt.wantConf {
				t.Errorf("confidence = %v, want %v", resp.Confidence, tt.wantConf)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	// Test empty provider returns error
	_, err := NewClient(Config{}, nil)
	if err == nil {
		t.Error("expected error for empty provider")
	}

	// Test unknown provider returns error
	_, err = NewClient(Config{Provider: "unknown"}, nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}
