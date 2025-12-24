package rspamd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mnohosten/esp/internal/filter"
)

// Config holds configuration for rspamd integration.
type Config struct {
	URL             string        `mapstructure:"url"`
	Password        string        `mapstructure:"password"`
	Timeout         time.Duration `mapstructure:"timeout"`
	RejectScore     float64       `mapstructure:"reject_score"`
	QuarantineScore float64       `mapstructure:"quarantine_score"`
	AddHeaders      bool          `mapstructure:"add_headers"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		URL:             "http://localhost:11333",
		Timeout:         30 * time.Second,
		RejectScore:     15.0,
		QuarantineScore: 6.0,
		AddHeaders:      true,
	}
}

// Client wraps rspamd HTTP API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	password   string
}

// NewClient creates a new rspamd client.
func NewClient(baseURL, password string, timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL:  strings.TrimRight(baseURL, "/"),
		password: password,
	}
}

// CheckRequest holds parameters for a check request.
type CheckRequest struct {
	IP       string
	Hostname string
	HELO     string
	From     string
	Rcpt     []string
	User     string
	Pass     string
}

// CheckResponse holds rspamd check response.
type CheckResponse struct {
	IsSkipped     bool               `json:"is_skipped"`
	Score         float64            `json:"score"`
	RequiredScore float64            `json:"required_score"`
	Action        string             `json:"action"`
	Symbols       map[string]Symbol  `json:"symbols"`
	URLs          []string           `json:"urls"`
	Emails        []string           `json:"emails"`
	MessageID     string             `json:"message-id"`
	TimeReal      float64            `json:"time_real"`
	MilterHeaders *MilterHeaders     `json:"milter,omitempty"`
}

// Symbol represents a matched rspamd symbol.
type Symbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	MetricScore float64  `json:"metric_score"`
	Description string   `json:"description"`
	Options     []string `json:"options,omitempty"`
}

// MilterHeaders contains headers suggested by rspamd.
type MilterHeaders struct {
	Add    map[string]MilterHeader `json:"add_headers,omitempty"`
	Remove map[string]int          `json:"remove_headers,omitempty"`
}

// MilterHeader represents a header to add.
type MilterHeader struct {
	Value string `json:"value"`
	Order int    `json:"order"`
}

// Check sends a message to rspamd for checking.
func (c *Client) Check(ctx context.Context, body []byte, req *CheckRequest) (*CheckResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/checkv2", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	if c.password != "" {
		httpReq.Header.Set("Password", c.password)
	}

	// Add rspamd-specific headers
	if req != nil {
		if req.IP != "" {
			httpReq.Header.Set("IP", req.IP)
		}
		if req.Hostname != "" {
			httpReq.Header.Set("Hostname", req.Hostname)
		}
		if req.HELO != "" {
			httpReq.Header.Set("Helo", req.HELO)
		}
		if req.From != "" {
			httpReq.Header.Set("From", req.From)
		}
		for _, rcpt := range req.Rcpt {
			httpReq.Header.Add("Rcpt", rcpt)
		}
		if req.User != "" {
			httpReq.Header.Set("User", req.User)
		}
		if req.Pass != "" {
			httpReq.Header.Set("Pass", req.Pass)
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rspamd returned status %d: %s", resp.StatusCode, string(body))
	}

	var result CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// Ping checks if rspamd is available.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ping", nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd returned status %d", resp.StatusCode)
	}

	return nil
}

// Filter implements rspamd spam checking.
type Filter struct {
	client *Client
	config Config
	logger *slog.Logger
}

// NewFilter creates a new rspamd filter.
func NewFilter(config Config, logger *slog.Logger) *Filter {
	return &Filter{
		client: NewClient(config.URL, config.Password, config.Timeout),
		config: config,
		logger: logger,
	}
}

// Name returns the filter name.
func (f *Filter) Name() string { return "rspamd" }

// Priority returns the filter priority.
func (f *Filter) Priority() int { return 100 }

// Process processes a message through rspamd.
func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
	// Build rspamd request
	req := &CheckRequest{
		From: msg.From,
		Rcpt: msg.To,
		User: msg.AuthUser,
	}

	if msg.ClientIP != nil {
		req.IP = msg.ClientIP.String()
	}
	if msg.ClientHost != "" {
		req.Hostname = msg.ClientHost
	}
	if msg.HELO != "" {
		req.HELO = msg.HELO
	}

	// Send to rspamd
	resp, err := f.client.Check(ctx, msg.Body, req)
	if err != nil {
		return nil, fmt.Errorf("rspamd check failed: %w", err)
	}

	// Extract symbol names
	var symbols []string
	for name := range resp.Symbols {
		symbols = append(symbols, name)
	}

	result := &filter.Result{
		Score: resp.Score,
		Tags:  symbols,
		Metadata: map[string]any{
			"rspamd_action":         resp.Action,
			"rspamd_score":          resp.Score,
			"rspamd_required_score": resp.RequiredScore,
			"rspamd_symbols":        resp.Symbols,
			"rspamd_is_skipped":     resp.IsSkipped,
		},
	}

	// Add spam headers if configured
	if f.config.AddHeaders {
		result.Headers = make(map[string]string)
		result.Headers["X-Spam-Score"] = fmt.Sprintf("%.2f", resp.Score)
		result.Headers["X-Spam-Status"] = resp.Action

		if len(symbols) > 0 {
			result.Headers["X-Spam-Symbols"] = strings.Join(symbols, ", ")
		}

		// Include milter headers if present
		if resp.MilterHeaders != nil && resp.MilterHeaders.Add != nil {
			for name, header := range resp.MilterHeaders.Add {
				result.Headers[name] = header.Value
			}
		}
	}

	// Determine action based on score thresholds
	switch {
	case resp.Score >= f.config.RejectScore:
		result.Action = filter.ActionReject
		result.Reason = fmt.Sprintf("spam score %.2f exceeds reject threshold %.2f", resp.Score, f.config.RejectScore)
		f.logger.Info("message rejected by rspamd",
			"message_id", msg.ID,
			"score", resp.Score,
			"threshold", f.config.RejectScore,
		)
	case resp.Score >= f.config.QuarantineScore:
		result.Action = filter.ActionQuarantine
		result.TargetFolder = "Junk"
		result.Reason = fmt.Sprintf("spam score %.2f exceeds quarantine threshold %.2f", resp.Score, f.config.QuarantineScore)
		f.logger.Info("message quarantined by rspamd",
			"message_id", msg.ID,
			"score", resp.Score,
			"threshold", f.config.QuarantineScore,
		)
	default:
		result.Action = filter.ActionAccept
	}

	// Also respect rspamd's own action recommendation
	switch resp.Action {
	case "reject":
		if result.Action < filter.ActionReject {
			result.Action = filter.ActionReject
			result.Reason = "rspamd recommends reject"
		}
	case "soft reject":
		if result.Action < filter.ActionDefer {
			result.Action = filter.ActionDefer
			result.Reason = "rspamd recommends soft reject"
		}
	case "add header", "rewrite subject":
		if result.Action < filter.ActionQuarantine {
			result.Action = filter.ActionQuarantine
			result.TargetFolder = "Junk"
		}
	}

	return result, nil
}

// Ping checks if rspamd is available.
func (f *Filter) Ping(ctx context.Context) error {
	return f.client.Ping(ctx)
}
