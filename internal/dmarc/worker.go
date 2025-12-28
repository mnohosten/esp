package dmarc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Worker handles scheduled DMARC report generation and sending.
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

// WorkerConfig contains configuration for the DMARC worker.
type WorkerConfig struct {
	Enabled        bool
	ReportTime     string        // Time to generate daily reports (e.g., "02:00")
	RetryIntervals []time.Duration
	MaxRetries     int
}

// NewWorker creates a new DMARC worker.
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
		config.ReportTime = "02:00"
	}

	return &Worker{
		store:     store,
		generator: generator,
		parser:    parser,
		config:    config,
		logger:    logger.With("component", "dmarc.worker"),
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

	w.logger.Info("starting DMARC worker", "report_time", w.config.ReportTime)

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

	w.logger.Info("stopping DMARC worker")

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		w.logger.Info("DMARC worker stopped")
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

	// Also check pending sends periodically
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
	hour, minute := 2, 0 // Default to 02:00
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
	w.logger.Info("starting daily DMARC report generation")

	// Get yesterday's date for the report period
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Truncate(24 * time.Hour)
	start := yesterday
	end := yesterday.Add(24*time.Hour - time.Second)

	// Get domains with pending results
	domains, err := w.store.GetDomainsWithPendingResults(ctx, time.Now().UTC().Truncate(24*time.Hour))
	if err != nil {
		w.logger.Error("failed to get domains with pending results", "error", err)
		return
	}

	w.logger.Info("found domains with pending auth results", "count", len(domains))

	for _, domain := range domains {
		if err := w.generateReportForDomain(ctx, domain, start, end); err != nil {
			w.logger.Error("failed to generate report for domain",
				"domain", domain,
				"error", err,
			)
		}
	}

	w.logger.Info("completed daily DMARC report generation")
}

// generateReportForDomain generates a report for a single domain.
func (w *Worker) generateReportForDomain(ctx context.Context, domain string, start, end time.Time) error {
	// Look up RUA addresses
	ruaAddresses, err := w.generator.LookupRUAAddresses(ctx, domain)
	if err != nil {
		w.logger.Debug("no RUA addresses found for domain", "domain", domain, "error", err)
		// Clean up auth results even if no RUA
		reportDate := start.UTC().Truncate(24 * time.Hour)
		w.store.DeleteAuthResultsForDate(ctx, domain, reportDate)
		return nil
	}

	if len(ruaAddresses) == 0 {
		w.logger.Debug("no RUA addresses in DMARC record", "domain", domain)
		reportDate := start.UTC().Truncate(24 * time.Hour)
		w.store.DeleteAuthResultsForDate(ctx, domain, reportDate)
		return nil
	}

	// Generate the report
	report, err := w.generator.GenerateReport(ctx, domain, start, end)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if report == nil || len(report.Records) == 0 {
		w.logger.Debug("no records for report", "domain", domain)
		reportDate := start.UTC().Truncate(24 * time.Hour)
		w.store.DeleteAuthResultsForDate(ctx, domain, reportDate)
		return nil
	}

	// Serialize to XML
	xmlData, err := w.generator.ToXML(report)
	if err != nil {
		return fmt.Errorf("failed to serialize report: %w", err)
	}

	// Compress
	compressed, err := w.generator.CompressReport(xmlData)
	if err != nil {
		return fmt.Errorf("failed to compress report: %w", err)
	}

	// Validate external RUA addresses
	var validAddresses []string
	for _, addr := range ruaAddresses {
		valid, err := w.generator.ValidateExternalRUA(ctx, domain, addr)
		if err != nil {
			w.logger.Warn("failed to validate external RUA",
				"domain", domain,
				"rua", addr,
				"error", err,
			)
			continue
		}
		if valid {
			validAddresses = append(validAddresses, addr)
		} else {
			w.logger.Debug("external RUA not authorized",
				"domain", domain,
				"rua", addr,
			)
		}
	}

	if len(validAddresses) == 0 {
		w.logger.Warn("no valid RUA addresses for domain", "domain", domain)
		reportDate := start.UTC().Truncate(24 * time.Hour)
		w.store.DeleteAuthResultsForDate(ctx, domain, reportDate)
		return nil
	}

	// Save the sent report
	sentReport := &SentReport{
		Domain:           domain,
		RUAAddresses:     validAddresses,
		DateBegin:        start,
		DateEnd:          end,
		ReportID:         report.ReportMetadata.ReportID,
		RecordCount:      len(report.Records),
		ReportXML:        string(xmlData),
		CompressedReport: compressed,
		Status:           string(ReportStatusPending),
	}

	if err := w.store.SaveSentReport(ctx, sentReport); err != nil {
		return fmt.Errorf("failed to save sent report: %w", err)
	}

	w.logger.Info("queued DMARC report for sending",
		"domain", domain,
		"report_id", report.ReportMetadata.ReportID,
		"records", len(report.Records),
		"rua_addresses", len(validAddresses),
	)

	// Clean up processed auth results
	reportDate := start.UTC().Truncate(24 * time.Hour)
	w.store.DeleteAuthResultsForDate(ctx, domain, reportDate)

	return nil
}

// processPendingSends attempts to send any pending reports.
func (w *Worker) processPendingSends(ctx context.Context) {
	// This would be implemented with actual email sending
	// For now, we just log that it would happen
	reports, _, err := w.store.GetSentReports(ctx, ReportFilter{Status: string(ReportStatusPending)}, 1, 50)
	if err != nil {
		w.logger.Error("failed to get pending reports", "error", err)
		return
	}

	for _, report := range reports {
		if err := w.sendReport(ctx, &report); err != nil {
			w.logger.Error("failed to send report",
				"report_id", report.ReportID,
				"domain", report.Domain,
				"error", err,
			)
			w.store.UpdateSentReportStatus(ctx, report.ID, ReportStatusFailed, err.Error())
		} else {
			w.store.UpdateSentReportStatus(ctx, report.ID, ReportStatusSent, "")
		}
	}
}

// sendReport sends a single report via email.
func (w *Worker) sendReport(ctx context.Context, report *SentReport) error {
	// TODO: Implement actual email sending
	// This would:
	// 1. Create a MIME message with the compressed report as attachment
	// 2. Set appropriate headers (From, To, Subject)
	// 3. Send via SMTP to each RUA address
	//
	// For now, just mark as sent
	w.logger.Info("would send DMARC report",
		"report_id", report.ReportID,
		"domain", report.Domain,
		"rua_addresses", report.RUAAddresses,
	)

	return nil
}

// ProcessIncomingReport processes an incoming DMARC report from email.
func (w *Worker) ProcessIncomingReport(ctx context.Context, messageData []byte, sourceIP string, sourceEmail string) error {
	report, rawXML, err := w.parser.ParseFromMIME(messageData)
	if err != nil {
		return fmt.Errorf("failed to parse DMARC report: %w", err)
	}

	var ip net.IP
	if sourceIP != "" {
		ip = net.ParseIP(sourceIP)
	}

	_, err = w.store.SaveReceivedReport(ctx, report, rawXML, ip, sourceEmail)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	w.logger.Info("processed incoming DMARC report",
		"org_name", report.ReportMetadata.OrgName,
		"report_id", report.ReportMetadata.ReportID,
		"domain", report.PolicyPublished.Domain,
		"records", len(report.Records),
	)

	return nil
}
