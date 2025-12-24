package queue

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// WorkerPool manages a pool of delivery workers.
type WorkerPool struct {
	manager    *Manager
	workers    int
	hostname   string
	tlsConfig  *tls.Config
	logger     *slog.Logger

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewWorkerPool creates a new worker pool.
func NewWorkerPool(manager *Manager, workers int, hostname string, tlsConfig *tls.Config, logger *slog.Logger) *WorkerPool {
	return &WorkerPool{
		manager:   manager,
		workers:   workers,
		hostname:  hostname,
		tlsConfig: tlsConfig,
		logger:    logger.With("component", "queue.worker"),
	}
}

// Start starts the worker pool.
func (p *WorkerPool) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("worker pool already running")
	}
	p.running = true
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	p.logger.Info("starting worker pool", "workers", p.workers)

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx, i)
	}

	return nil
}

// Stop stops the worker pool gracefully.
func (p *WorkerPool) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	close(p.stopCh)
	p.mu.Unlock()

	p.logger.Info("stopping worker pool")

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("worker pool stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runWorker runs a single worker loop.
func (p *WorkerPool) runWorker(ctx context.Context, id int) {
	defer p.wg.Done()

	logger := p.logger.With("worker_id", id)
	logger.Debug("worker started")

	pollInterval := p.manager.config.PollInterval
	if pollInterval == 0 {
		pollInterval = 10 * time.Second
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			logger.Debug("worker stopped")
			return
		case <-ctx.Done():
			logger.Debug("worker context cancelled")
			return
		case <-ticker.C:
			p.processOne(ctx, logger)
		}
	}
}

// processOne attempts to process a single message.
func (p *WorkerPool) processOne(ctx context.Context, logger *slog.Logger) {
	msg, err := p.manager.Dequeue(ctx)
	if err != nil {
		logger.Error("failed to dequeue message", "error", err)
		return
	}

	if msg == nil {
		// No messages available
		return
	}

	logger = logger.With("message_id", msg.ID, "recipient", msg.Recipient)
	logger.Debug("processing message")

	result := p.deliver(ctx, msg)

	if result.Success {
		if err := p.manager.Complete(ctx, msg.ID); err != nil {
			logger.Error("failed to complete message", "error", err)
		}
	} else if result.Permanent {
		if err := p.manager.Bounce(ctx, msg.ID, result.Error); err != nil {
			logger.Error("failed to bounce message", "error", err)
		}
	} else {
		if err := p.manager.Defer(ctx, msg.ID, result); err != nil {
			logger.Error("failed to defer message", "error", err)
		}
	}
}

// deliver attempts to deliver a message to its recipient.
func (p *WorkerPool) deliver(ctx context.Context, msg *Message) *DeliveryResult {
	// Extract recipient domain
	parts := strings.Split(msg.Recipient, "@")
	if len(parts) != 2 {
		return &DeliveryResult{
			Success:   false,
			Permanent: true,
			Error:     "invalid recipient address",
		}
	}
	domain := parts[1]

	// Resolve MX records
	mxHosts, err := p.resolveMX(ctx, domain)
	if err != nil {
		return &DeliveryResult{
			Success:   false,
			Permanent: false, // DNS failures are temporary
			Error:     fmt.Sprintf("MX lookup failed: %v", err),
		}
	}

	if len(mxHosts) == 0 {
		return &DeliveryResult{
			Success:   false,
			Permanent: true,
			Error:     "no MX records found",
		}
	}

	// Read message content
	content, err := os.ReadFile(msg.MessagePath)
	if err != nil {
		return &DeliveryResult{
			Success:   false,
			Permanent: true,
			Error:     fmt.Sprintf("failed to read message: %v", err),
		}
	}

	// Try each MX host in order of preference
	var lastErr error
	for _, mx := range mxHosts {
		result := p.deliverToMX(ctx, mx, msg, content)
		if result.Success {
			return result
		}

		// If permanent failure, don't try other MX hosts
		if result.Permanent {
			return result
		}

		lastErr = fmt.Errorf("%s: %s", mx, result.Error)
	}

	return &DeliveryResult{
		Success:   false,
		Permanent: false,
		Error:     fmt.Sprintf("all MX hosts failed: %v", lastErr),
	}
}

// resolveMX resolves and returns MX hosts for a domain, sorted by preference.
func (p *WorkerPool) resolveMX(ctx context.Context, domain string) ([]string, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		// If no MX records, try the domain itself (RFC 5321)
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			// Check if domain has an A/AAAA record
			_, err := net.LookupHost(domain)
			if err == nil {
				return []string{domain}, nil
			}
		}
		return nil, err
	}

	if len(mxRecords) == 0 {
		// Fall back to domain itself
		return []string{domain}, nil
	}

	// Sort by preference (lower is better)
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	hosts := make([]string, len(mxRecords))
	for i, mx := range mxRecords {
		hosts[i] = strings.TrimSuffix(mx.Host, ".")
	}

	return hosts, nil
}

// deliverToMX attempts to deliver to a specific MX host.
func (p *WorkerPool) deliverToMX(ctx context.Context, mx string, msg *Message, content []byte) *DeliveryResult {
	// Try port 25
	addr := net.JoinHostPort(mx, "25")

	// Connect with timeout
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &DeliveryResult{
			Success:    false,
			Permanent:  false,
			Error:      fmt.Sprintf("connection failed: %v", err),
			RemoteHost: mx,
		}
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Create SMTP client
	client, err := smtp.NewClient(conn, mx)
	if err != nil {
		return &DeliveryResult{
			Success:    false,
			Permanent:  false,
			Error:      fmt.Sprintf("SMTP client error: %v", err),
			RemoteHost: mx,
		}
	}
	defer client.Close()

	// Say hello
	if err := client.Hello(p.hostname); err != nil {
		return &DeliveryResult{
			Success:    false,
			Permanent:  false,
			Error:      fmt.Sprintf("HELO failed: %v", err),
			RemoteHost: mx,
		}
	}

	// Try STARTTLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: mx,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			// Log but continue without TLS
			p.logger.Warn("STARTTLS failed, continuing without TLS",
				"mx", mx,
				"error", err,
			)
		}
	}

	// Set sender
	if err := client.Mail(msg.Sender); err != nil {
		code, message := parseSmtpError(err)
		return &DeliveryResult{
			Success:      false,
			Permanent:    isPermanentError(code),
			Error:        fmt.Sprintf("MAIL FROM rejected: %v", err),
			RemoteHost:   mx,
			ResponseCode: code,
			ResponseMsg:  message,
		}
	}

	// Set recipient
	if err := client.Rcpt(msg.Recipient); err != nil {
		code, message := parseSmtpError(err)
		return &DeliveryResult{
			Success:      false,
			Permanent:    isPermanentError(code),
			Error:        fmt.Sprintf("RCPT TO rejected: %v", err),
			RemoteHost:   mx,
			ResponseCode: code,
			ResponseMsg:  message,
		}
	}

	// Send data
	w, err := client.Data()
	if err != nil {
		code, message := parseSmtpError(err)
		return &DeliveryResult{
			Success:      false,
			Permanent:    isPermanentError(code),
			Error:        fmt.Sprintf("DATA rejected: %v", err),
			RemoteHost:   mx,
			ResponseCode: code,
			ResponseMsg:  message,
		}
	}

	_, err = io.Copy(w, strings.NewReader(string(content)))
	if err != nil {
		w.Close()
		return &DeliveryResult{
			Success:    false,
			Permanent:  false,
			Error:      fmt.Sprintf("failed to send message body: %v", err),
			RemoteHost: mx,
		}
	}

	if err := w.Close(); err != nil {
		code, message := parseSmtpError(err)
		return &DeliveryResult{
			Success:      false,
			Permanent:    isPermanentError(code),
			Error:        fmt.Sprintf("message rejected: %v", err),
			RemoteHost:   mx,
			ResponseCode: code,
			ResponseMsg:  message,
		}
	}

	// Quit
	client.Quit()

	return &DeliveryResult{
		Success:    true,
		RemoteHost: mx,
	}
}

// parseSmtpError extracts the SMTP response code from an error.
func parseSmtpError(err error) (int, string) {
	if err == nil {
		return 0, ""
	}

	errStr := err.Error()

	// Try to parse SMTP error code (e.g., "550 User not found")
	var code int
	var message string
	if len(errStr) >= 3 {
		fmt.Sscanf(errStr, "%d %s", &code, &message)
		if code >= 100 && code <= 599 {
			return code, errStr
		}
	}

	return 0, errStr
}

// isPermanentError returns true if the SMTP code indicates a permanent failure.
func isPermanentError(code int) bool {
	// 5xx codes are permanent failures
	return code >= 500 && code <= 599
}
