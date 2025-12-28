package tlsrpt

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Worker handles scheduled TLS-RPT report generation and sending.
type Worker struct {
	store     *Store
	generator *Generator
	parser    *Parser
	config    WorkerConfig
	logger    *slog.Logger

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// WorkerConfig contains configuration for the TLS-RPT worker.
type WorkerConfig struct {
	Enabled        bool
	ReportTime     string // Time to generate daily reports (e.g., "03:00")
	RetryIntervals []time.Duration
	MaxRetries     int
	CleanupAge     time.Duration // How long to keep old results
}

// NewWorker creates a new TLS-RPT worker.
func NewWorker(store *Store, generator *Generator, parser *Parser, logger *slog.Logger, config WorkerConfig) *Worker {
	if len(config.RetryIntervals) == 0 {
		config.RetryIntervals = []time.Duration{
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
			4 * time.Hour,
		}
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 5
	}
	if config.ReportTime == "" {
		config.ReportTime = "03:00"
	}
	if config.CleanupAge == 0 {
		config.CleanupAge = 30 * 24 * time.Hour // 30 days
	}

	return &Worker{
		store:     store,
		generator: generator,
		parser:    parser,
		config:    config,
		logger:    logger.With("component", "tlsrpt.worker"),
	}
}

// Start begins the worker loop.
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("worker already running")
	}
	w.running = true
	w.stopCh = make(chan struct{})
	w.mu.Unlock()

	w.logger.Info("starting TLS-RPT worker", "report_time", w.config.ReportTime)

	w.wg.Add(1)
	go w.runLoop(ctx)

	return nil
}

// Stop gracefully stops the worker.
func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	close(w.stopCh)
	w.mu.Unlock()

	w.logger.Info("stopping TLS-RPT worker")

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		w.logger.Info("TLS-RPT worker stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runLoop is the main worker loop.
func (w *Worker) runLoop(ctx context.Context) {
	defer w.wg.Done()

	// Calculate time until next report run
	nextRun := w.nextReportTime()
	timer := time.NewTimer(time.Until(nextRun))
	defer timer.Stop()

	// Also process pending sends and cleanup periodically
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ctx.Done():
			return
		case <-timer.C:
			w.runDailyReports(ctx)
			w.cleanup(ctx)
			nextRun = w.nextReportTime()
			timer.Reset(time.Until(nextRun))
		case <-ticker.C:
			w.processPendingSends(ctx)
		}
	}
}

// nextReportTime calculates the next time reports should be generated.
func (w *Worker) nextReportTime() time.Time {
	now := time.Now().UTC()

	// Parse configured time
	hour, minute := 3, 0 // Default to 03:00
	fmt.Sscanf(w.config.ReportTime, "%d:%d", &hour, &minute)

	// Calculate next run time
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
	if next.Before(now) || next.Equal(now) {
		next = next.Add(24 * time.Hour)
	}

	return next
}

// runDailyReports generates and queues reports for all domains.
func (w *Worker) runDailyReports(ctx context.Context) {
	w.logger.Info("starting daily TLS-RPT report generation")

	// Get yesterday's date for the report period
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Truncate(24 * time.Hour)
	start := yesterday
	end := yesterday.Add(24 * time.Hour)

	// Get domains with results
	domains, err := w.store.GetDomainsWithResults(ctx, yesterday)
	if err != nil {
		w.logger.Error("failed to get domains with results", "error", err)
		return
	}

	w.logger.Info("found domains with TLS results", "count", len(domains))

	for _, domain := range domains {
		if err := w.generateReportForDomain(ctx, domain, start, end); err != nil {
			w.logger.Error("failed to generate report for domain",
				"domain", domain,
				"error", err,
			)
		}
	}

	w.logger.Info("completed daily TLS-RPT report generation")
}

// generateReportForDomain generates a report for a single domain.
func (w *Worker) generateReportForDomain(ctx context.Context, domain string, start, end time.Time) error {
	// Look up RUA addresses
	ruaAddresses, err := w.generator.LookupRUAAddresses(ctx, domain)
	if err != nil {
		w.logger.Debug("no TLS-RPT addresses found for domain", "domain", domain, "error", err)
		return nil
	}

	if len(ruaAddresses) == 0 {
		w.logger.Debug("no RUA addresses in TLS-RPT record", "domain", domain)
		return nil
	}

	// Generate the report
	report, err := w.generator.GenerateReport(ctx, domain, start, end)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if report == nil || len(report.Policies) == 0 {
		w.logger.Debug("no policies for report", "domain", domain)
		return nil
	}

	// Create and save sent report for each RUA
	for _, rua := range ruaAddresses {
		sentReport, err := w.generator.PrepareForSending(report, rua)
		if err != nil {
			w.logger.Error("failed to prepare report for sending",
				"domain", domain,
				"rua", rua,
				"error", err,
			)
			continue
		}

		if err := w.store.SaveSentReport(ctx, sentReport); err != nil {
			w.logger.Error("failed to save sent report",
				"domain", domain,
				"rua", rua,
				"error", err,
			)
			continue
		}

		w.logger.Info("queued TLS-RPT report for sending",
			"domain", domain,
			"report_id", report.ReportID,
			"rua", rua,
		)
	}

	return nil
}

// processPendingSends attempts to send any pending reports.
func (w *Worker) processPendingSends(ctx context.Context) {
	reports, _, err := w.store.GetSentReports(ctx, ReportFilter{Status: ReportStatusPending}, 1, 50)
	if err != nil {
		w.logger.Error("failed to get pending reports", "error", err)
		return
	}

	for _, report := range reports {
		if err := w.sendReport(ctx, &report); err != nil {
			w.logger.Error("failed to send report",
				"report_id", report.ReportID,
				"domain", report.PolicyDomain,
				"error", err,
			)
			w.store.UpdateSentReportStatus(ctx, report.ID, ReportStatusFailed, err.Error())
		} else {
			w.store.UpdateSentReportStatus(ctx, report.ID, ReportStatusSent, "")
		}
	}
}

// sendReport sends a single report.
func (w *Worker) sendReport(ctx context.Context, report *SentReport) error {
	// TODO: Implement actual sending
	// For mailto: URIs, send via SMTP
	// For https: URIs, POST to the endpoint

	w.logger.Info("would send TLS-RPT report",
		"report_id", report.ReportID,
		"domain", report.PolicyDomain,
		"rua", report.RUAURI,
	)

	return nil
}

// cleanup removes old connection results.
func (w *Worker) cleanup(ctx context.Context) {
	before := time.Now().Add(-w.config.CleanupAge)
	count, err := w.store.DeleteOldResults(ctx, before)
	if err != nil {
		w.logger.Error("failed to cleanup old results", "error", err)
		return
	}
	if count > 0 {
		w.logger.Info("cleaned up old TLS connection results", "count", count)
	}
}

// ProcessIncomingReport processes an incoming TLS-RPT report from email.
func (w *Worker) ProcessIncomingReport(ctx context.Context, messageData []byte, sourceIP string) error {
	report, policyDomain, err := w.parser.ParseFromMIME(messageData)
	if err != nil {
		return fmt.Errorf("failed to parse TLS-RPT report: %w", err)
	}

	var _ net.IP
	if sourceIP != "" {
		_ = net.ParseIP(sourceIP)
	}

	_, err = w.store.SaveReceivedReport(ctx, report, policyDomain)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	// Calculate totals for logging
	var totalSuccess, totalFailed int
	for _, p := range report.Policies {
		totalSuccess += p.Summary.TotalSuccessfulSessionCount
		totalFailed += p.Summary.TotalFailureSessionCount
	}

	w.logger.Info("processed incoming TLS-RPT report",
		"org_name", report.OrganizationName,
		"report_id", report.ReportID,
		"policy_domain", policyDomain,
		"successful", totalSuccess,
		"failed", totalFailed,
	)

	return nil
}
