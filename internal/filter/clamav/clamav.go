package clamav

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mnohosten/esp/internal/filter"
)

// Config holds configuration for ClamAV integration.
type Config struct {
	Address string        `mapstructure:"address"` // tcp://host:port or unix:///path/to/socket
	Timeout time.Duration `mapstructure:"timeout"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Address: "tcp://localhost:3310",
		Timeout: 60 * time.Second,
	}
}

// ScanResult holds the result of a ClamAV scan.
type ScanResult struct {
	Infected bool
	Virus    string
	Error    string
}

// Client wraps the clamd protocol.
type Client struct {
	network string
	address string
	timeout time.Duration
}

// NewClient creates a new ClamAV client.
func NewClient(address string, timeout time.Duration) (*Client, error) {
	network, addr, err := parseAddress(address)
	if err != nil {
		return nil, err
	}

	return &Client{
		network: network,
		address: addr,
		timeout: timeout,
	}, nil
}

// parseAddress parses a clamd address into network and address parts.
func parseAddress(address string) (network, addr string, err error) {
	switch {
	case strings.HasPrefix(address, "tcp://"):
		return "tcp", strings.TrimPrefix(address, "tcp://"), nil
	case strings.HasPrefix(address, "unix://"):
		return "unix", strings.TrimPrefix(address, "unix://"), nil
	default:
		// Assume TCP if no prefix
		if strings.Contains(address, ":") {
			return "tcp", address, nil
		}
		return "", "", fmt.Errorf("invalid clamd address: %s", address)
	}
}

// connect establishes a connection to clamd.
func (c *Client) connect(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}
	return dialer.DialContext(ctx, c.network, c.address)
}

// Ping checks if clamd is available.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to clamd: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}

	// Send PING command
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		return fmt.Errorf("failed to send PING: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "PONG" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// Version returns the ClamAV version.
func (c *Client) Version(ctx context.Context) (string, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to connect to clamd: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", err
	}

	// Send VERSION command
	if _, err := conn.Write([]byte("VERSION\n")); err != nil {
		return "", fmt.Errorf("failed to send VERSION: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return strings.TrimSpace(response), nil
}

// ScanStream scans data from a reader using INSTREAM command.
func (c *Client) ScanStream(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to clamd: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}

	// Send INSTREAM command
	if _, err := conn.Write([]byte("nINSTREAM\n")); err != nil {
		return nil, fmt.Errorf("failed to send INSTREAM: %w", err)
	}

	// Stream data in chunks
	// INSTREAM protocol: send chunks with 4-byte big-endian length prefix
	// End with zero-length chunk
	buf := make([]byte, 8192)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			// Write chunk length
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return nil, fmt.Errorf("failed to write chunk length: %w", err)
			}
			// Write chunk data
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, fmt.Errorf("failed to write chunk data: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to read data: %w", readErr)
		}
	}

	// Send zero-length chunk to indicate end
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("failed to send end marker: %w", err)
	}

	// Read response
	respReader := bufio.NewReader(conn)
	response, err := respReader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return parseResponse(response)
}

// ScanBytes scans a byte slice.
func (c *Client) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	return c.ScanStream(ctx, bytes.NewReader(data))
}

// parseResponse parses a clamd response.
func parseResponse(response string) (*ScanResult, error) {
	response = strings.TrimSpace(response)

	// Response format: "stream: OK" or "stream: VirusName FOUND" or "stream: ERROR message"
	if strings.HasSuffix(response, " OK") {
		return &ScanResult{Infected: false}, nil
	}

	if strings.HasSuffix(response, " FOUND") {
		// Extract virus name
		parts := strings.SplitN(response, ": ", 2)
		if len(parts) == 2 {
			virusName := strings.TrimSuffix(parts[1], " FOUND")
			return &ScanResult{
				Infected: true,
				Virus:    virusName,
			}, nil
		}
		return &ScanResult{
			Infected: true,
			Virus:    "Unknown",
		}, nil
	}

	if strings.Contains(response, " ERROR") {
		parts := strings.SplitN(response, " ERROR", 2)
		errorMsg := "unknown error"
		if len(parts) == 2 {
			errorMsg = strings.TrimSpace(parts[1])
		}
		return &ScanResult{
			Error: errorMsg,
		}, fmt.Errorf("clamd error: %s", errorMsg)
	}

	return nil, fmt.Errorf("unexpected clamd response: %s", response)
}

// Filter implements ClamAV virus scanning.
type Filter struct {
	client *Client
	config Config
	logger *slog.Logger
}

// NewFilter creates a new ClamAV filter.
func NewFilter(config Config, logger *slog.Logger) (*Filter, error) {
	client, err := NewClient(config.Address, config.Timeout)
	if err != nil {
		return nil, err
	}

	return &Filter{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// Name returns the filter name.
func (f *Filter) Name() string { return "clamav" }

// Priority returns the filter priority.
// Virus scanning runs before spam filtering.
func (f *Filter) Priority() int { return 50 }

// Process processes a message through ClamAV.
func (f *Filter) Process(ctx context.Context, msg *filter.Message) (*filter.Result, error) {
	result, err := f.client.ScanBytes(ctx, msg.Body)
	if err != nil {
		return nil, fmt.Errorf("clamav scan failed: %w", err)
	}

	filterResult := &filter.Result{
		Action: filter.ActionAccept,
		Metadata: map[string]any{
			"clamav_scanned": true,
		},
	}

	if result.Infected {
		filterResult.Action = filter.ActionReject
		filterResult.Reason = fmt.Sprintf("virus detected: %s", result.Virus)
		filterResult.Tags = []string{"virus", result.Virus}
		filterResult.Metadata["clamav_virus"] = result.Virus
		filterResult.Headers = map[string]string{
			"X-Virus-Scanned": "ClamAV",
			"X-Virus-Status":  "Infected",
		}

		f.logger.Warn("virus detected",
			"message_id", msg.ID,
			"virus", result.Virus,
		)
	} else {
		filterResult.Headers = map[string]string{
			"X-Virus-Scanned": "ClamAV",
			"X-Virus-Status":  "Clean",
		}
	}

	return filterResult, nil
}

// Ping checks if ClamAV is available.
func (f *Filter) Ping(ctx context.Context) error {
	return f.client.Ping(ctx)
}

// Version returns the ClamAV version.
func (f *Filter) Version(ctx context.Context) (string, error) {
	return f.client.Version(ctx)
}
