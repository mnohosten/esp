package dmarc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles DMARC report database operations.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewStore creates a new DMARC store.
func NewStore(pool *pgxpool.Pool, logger *slog.Logger) *Store {
	return &Store{
		pool:   pool,
		logger: logger.With("component", "dmarc.store"),
	}
}

// SaveReceivedReport stores a parsed incoming DMARC report.
func (s *Store) SaveReceivedReport(ctx context.Context, report *AggregateReport, rawXML string, sourceIP net.IP, sourceEmail string) (*ReceivedReport, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert the main report
	var reportID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO dmarc_reports_received (
			org_name, email, extra_contact_info, report_id,
			date_begin, date_end, domain, adkim, aspf,
			policy, subdomain_policy, pct, raw_xml,
			source_ip, source_email
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (org_name, report_id) DO UPDATE SET
			date_begin = EXCLUDED.date_begin,
			date_end = EXCLUDED.date_end,
			received_at = NOW()
		RETURNING id`,
		report.ReportMetadata.OrgName,
		report.ReportMetadata.Email,
		report.ReportMetadata.ExtraContactInfo,
		report.ReportMetadata.ReportID,
		report.ReportMetadata.DateRange.BeginTime(),
		report.ReportMetadata.DateRange.EndTime(),
		report.PolicyPublished.Domain,
		report.PolicyPublished.ADKIM,
		report.PolicyPublished.ASPF,
		report.PolicyPublished.Policy,
		report.PolicyPublished.SubdomainPolicy,
		report.PolicyPublished.Percentage,
		rawXML,
		sourceIP,
		sourceEmail,
	).Scan(&reportID)
	if err != nil {
		return nil, fmt.Errorf("failed to insert report: %w", err)
	}

	// Insert records
	for _, record := range report.Records {
		authResultsJSON, _ := json.Marshal(&AuthResultsJSON{
			DKIM: record.AuthResults.DKIM,
			SPF:  record.AuthResults.SPF,
		})

		_, err = tx.Exec(ctx, `
			INSERT INTO dmarc_report_records (
				report_id, source_ip, count, disposition,
				dkim_result, spf_result, envelope_to, envelope_from,
				header_from, auth_results
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			reportID,
			record.Row.SourceIP,
			record.Row.Count,
			record.Row.PolicyEvaluated.Disposition,
			record.Row.PolicyEvaluated.DKIM,
			record.Row.PolicyEvaluated.SPF,
			record.Identifiers.EnvelopeTo,
			record.Identifiers.EnvelopeFrom,
			record.Identifiers.HeaderFrom,
			authResultsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert record: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	s.logger.Info("saved DMARC report",
		"report_id", report.ReportMetadata.ReportID,
		"org_name", report.ReportMetadata.OrgName,
		"domain", report.PolicyPublished.Domain,
		"records", len(report.Records),
	)

	return &ReceivedReport{
		ID:        reportID,
		OrgName:   report.ReportMetadata.OrgName,
		ReportID:  report.ReportMetadata.ReportID,
		Domain:    report.PolicyPublished.Domain,
		DateBegin: report.ReportMetadata.DateRange.BeginTime(),
		DateEnd:   report.ReportMetadata.DateRange.EndTime(),
	}, nil
}

// SaveAuthResult records an authentication result for DMARC aggregation.
func (s *Store) SaveAuthResult(ctx context.Context, result *AuthResult) error {
	dkimResultsJSON, _ := json.Marshal(result.DKIMResults)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO dmarc_auth_results (
			message_id, header_from_domain, envelope_from_domain, envelope_to_domain,
			source_ip, spf_result, spf_domain, spf_aligned,
			dkim_results, dkim_aligned, dmarc_result, dmarc_policy,
			disposition, report_date
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		result.MessageID,
		result.HeaderFromDomain,
		result.EnvelopeFromDomain,
		result.EnvelopeToDomain,
		result.SourceIP,
		result.SPFResult,
		result.SPFDomain,
		result.SPFAligned,
		dkimResultsJSON,
		result.DKIMAligned,
		result.DMARCResult,
		result.DMARCPolicy,
		result.Disposition,
		result.ReportDate,
	)
	if err != nil {
		return fmt.Errorf("failed to save auth result: %w", err)
	}

	return nil
}

// GetReceivedReports returns received reports with optional filtering.
func (s *Store) GetReceivedReports(ctx context.Context, filter ReportFilter, page, perPage int) ([]ReceivedReport, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	// Build query
	query := `
		SELECT r.id, r.org_name, r.email, r.report_id, r.date_begin, r.date_end,
			   r.domain, r.adkim, r.aspf, r.policy, r.subdomain_policy, r.pct,
			   r.received_at, r.source_ip, r.source_email, r.created_at,
			   COUNT(rec.id) as record_count,
			   COALESCE(SUM(CASE WHEN rec.dkim_result = 'pass' OR rec.spf_result = 'pass' THEN rec.count ELSE 0 END), 0) as pass_count,
			   COALESCE(SUM(CASE WHEN rec.dkim_result != 'pass' AND rec.spf_result != 'pass' THEN rec.count ELSE 0 END), 0) as fail_count
		FROM dmarc_reports_received r
		LEFT JOIN dmarc_report_records rec ON rec.report_id = r.id
		WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Domain != "" {
		query += fmt.Sprintf(" AND r.domain = $%d", argNum)
		args = append(args, filter.Domain)
		argNum++
	}
	if filter.OrgName != "" {
		query += fmt.Sprintf(" AND r.org_name ILIKE $%d", argNum)
		args = append(args, "%"+filter.OrgName+"%")
		argNum++
	}
	if !filter.DateFrom.IsZero() {
		query += fmt.Sprintf(" AND r.date_begin >= $%d", argNum)
		args = append(args, filter.DateFrom)
		argNum++
	}
	if !filter.DateTo.IsZero() {
		query += fmt.Sprintf(" AND r.date_end <= $%d", argNum)
		args = append(args, filter.DateTo)
		argNum++
	}

	query += ` GROUP BY r.id ORDER BY r.received_at DESC`
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, perPage, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query reports: %w", err)
	}
	defer rows.Close()

	var reports []ReceivedReport
	for rows.Next() {
		var r ReceivedReport
		err := rows.Scan(
			&r.ID, &r.OrgName, &r.Email, &r.ReportID, &r.DateBegin, &r.DateEnd,
			&r.Domain, &r.ADKIM, &r.ASPF, &r.Policy, &r.SubdomainPolicy, &r.Percentage,
			&r.ReceivedAt, &r.SourceIP, &r.SourceEmail, &r.CreatedAt,
			&r.RecordCount, &r.PassCount, &r.FailCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan report: %w", err)
		}
		reports = append(reports, r)
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM dmarc_reports_received WHERE 1=1`
	countArgs := []interface{}{}
	argNum = 1
	if filter.Domain != "" {
		countQuery += fmt.Sprintf(" AND domain = $%d", argNum)
		countArgs = append(countArgs, filter.Domain)
		argNum++
	}
	if filter.OrgName != "" {
		countQuery += fmt.Sprintf(" AND org_name ILIKE $%d", argNum)
		countArgs = append(countArgs, "%"+filter.OrgName+"%")
		argNum++
	}

	var total int
	err = s.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count reports: %w", err)
	}

	return reports, total, nil
}

// GetReceivedReportByID returns a single received report with its records.
func (s *Store) GetReceivedReportByID(ctx context.Context, id uuid.UUID) (*ReceivedReport, []ReportRecord, error) {
	var r ReceivedReport
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_name, email, extra_contact_info, report_id,
			   date_begin, date_end, domain, adkim, aspf, policy,
			   subdomain_policy, pct, received_at, source_ip, source_email, created_at
		FROM dmarc_reports_received
		WHERE id = $1`, id,
	).Scan(
		&r.ID, &r.OrgName, &r.Email, &r.ExtraContactInfo, &r.ReportID,
		&r.DateBegin, &r.DateEnd, &r.Domain, &r.ADKIM, &r.ASPF, &r.Policy,
		&r.SubdomainPolicy, &r.Percentage, &r.ReceivedAt, &r.SourceIP, &r.SourceEmail, &r.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get report: %w", err)
	}

	// Get records
	rows, err := s.pool.Query(ctx, `
		SELECT id, report_id, source_ip, count, disposition,
			   dkim_result, spf_result, envelope_to, envelope_from,
			   header_from, auth_results, created_at
		FROM dmarc_report_records
		WHERE report_id = $1
		ORDER BY count DESC`, id,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get records: %w", err)
	}
	defer rows.Close()

	var records []ReportRecord
	for rows.Next() {
		var rec ReportRecord
		var authResultsJSON []byte
		err := rows.Scan(
			&rec.ID, &rec.ReportID, &rec.SourceIP, &rec.Count, &rec.Disposition,
			&rec.DKIMResult, &rec.SPFResult, &rec.EnvelopeTo, &rec.EnvelopeFrom,
			&rec.HeaderFrom, &authResultsJSON, &rec.CreatedAt,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to scan record: %w", err)
		}
		if len(authResultsJSON) > 0 {
			var ar AuthResultsJSON
			json.Unmarshal(authResultsJSON, &ar)
			rec.AuthResults = &ar
		}
		records = append(records, rec)
	}

	return &r, records, nil
}

// GetDomainStats returns DMARC statistics for a domain.
func (s *Store) GetDomainStats(ctx context.Context, domain string, start, end time.Time) (*DomainStats, error) {
	stats := &DomainStats{
		Domain:      domain,
		PeriodStart: start,
		PeriodEnd:   end,
	}

	// Get aggregated stats from received reports
	err := s.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(rec.count), 0) as total,
			COALESCE(SUM(CASE WHEN rec.dkim_result = 'pass' OR rec.spf_result = 'pass' THEN rec.count ELSE 0 END), 0) as pass,
			COALESCE(SUM(CASE WHEN rec.dkim_result != 'pass' AND rec.spf_result != 'pass' THEN rec.count ELSE 0 END), 0) as fail,
			COALESCE(SUM(CASE WHEN rec.dkim_result = 'pass' THEN rec.count ELSE 0 END), 0) as dkim_aligned,
			COALESCE(SUM(CASE WHEN rec.spf_result = 'pass' THEN rec.count ELSE 0 END), 0) as spf_aligned
		FROM dmarc_reports_received r
		JOIN dmarc_report_records rec ON rec.report_id = r.id
		WHERE r.domain = $1 AND r.date_begin >= $2 AND r.date_end <= $3`,
		domain, start, end,
	).Scan(&stats.TotalMessages, &stats.PassCount, &stats.FailCount, &stats.DKIMAlignedCount, &stats.SPFAlignedCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	if stats.TotalMessages > 0 {
		stats.PassRate = float64(stats.PassCount) / float64(stats.TotalMessages) * 100
	}

	// Get report count
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM dmarc_reports_received
		WHERE domain = $1 AND date_begin >= $2 AND date_end <= $3`,
		domain, start, end,
	).Scan(&stats.ReportsReceived)
	if err != nil {
		return nil, fmt.Errorf("failed to count reports: %w", err)
	}

	// Get reporting orgs
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT org_name FROM dmarc_reports_received
		WHERE domain = $1 AND date_begin >= $2 AND date_end <= $3
		ORDER BY org_name LIMIT 20`,
		domain, start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get orgs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var org string
		if err := rows.Scan(&org); err != nil {
			continue
		}
		stats.ReportingOrgs = append(stats.ReportingOrgs, org)
	}

	// Get top sources
	rows, err = s.pool.Query(ctx, `
		SELECT rec.source_ip,
			   SUM(rec.count) as total,
			   SUM(CASE WHEN rec.dkim_result = 'pass' OR rec.spf_result = 'pass' THEN rec.count ELSE 0 END) as pass,
			   SUM(CASE WHEN rec.dkim_result != 'pass' AND rec.spf_result != 'pass' THEN rec.count ELSE 0 END) as fail
		FROM dmarc_reports_received r
		JOIN dmarc_report_records rec ON rec.report_id = r.id
		WHERE r.domain = $1 AND r.date_begin >= $2 AND r.date_end <= $3
		GROUP BY rec.source_ip
		ORDER BY total DESC
		LIMIT 10`,
		domain, start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get sources: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var src SourceStats
		if err := rows.Scan(&src.SourceIP, &src.Count, &src.PassCount, &src.FailCount); err != nil {
			continue
		}
		stats.BySource = append(stats.BySource, src)
	}

	return stats, nil
}

// GetDomainsWithPendingResults returns domains that have auth results ready for aggregation.
func (s *Store) GetDomainsWithPendingResults(ctx context.Context, beforeDate time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT header_from_domain
		FROM dmarc_auth_results
		WHERE report_date < $1
		ORDER BY header_from_domain`,
		beforeDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// GetAuthResultsForDomain retrieves auth results for report generation.
func (s *Store) GetAuthResultsForDomain(ctx context.Context, domain string, reportDate time.Time) ([]AuthResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, message_id, header_from_domain, envelope_from_domain, envelope_to_domain,
			   source_ip, spf_result, spf_domain, spf_aligned,
			   dkim_results, dkim_aligned, dmarc_result, dmarc_policy,
			   disposition, received_at, report_date
		FROM dmarc_auth_results
		WHERE header_from_domain = $1 AND report_date = $2
		ORDER BY received_at`,
		domain, reportDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth results: %w", err)
	}
	defer rows.Close()

	var results []AuthResult
	for rows.Next() {
		var r AuthResult
		var dkimResultsJSON []byte
		err := rows.Scan(
			&r.ID, &r.MessageID, &r.HeaderFromDomain, &r.EnvelopeFromDomain, &r.EnvelopeToDomain,
			&r.SourceIP, &r.SPFResult, &r.SPFDomain, &r.SPFAligned,
			&dkimResultsJSON, &r.DKIMAligned, &r.DMARCResult, &r.DMARCPolicy,
			&r.Disposition, &r.ReceivedAt, &r.ReportDate,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan auth result: %w", err)
		}
		if len(dkimResultsJSON) > 0 {
			json.Unmarshal(dkimResultsJSON, &r.DKIMResults)
		}
		results = append(results, r)
	}

	return results, nil
}

// SaveSentReport saves an outbound DMARC report.
func (s *Store) SaveSentReport(ctx context.Context, report *SentReport) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dmarc_reports_sent (
			domain, rua_addresses, date_begin, date_end,
			report_id, record_count, report_xml, compressed_report,
			status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		report.Domain, report.RUAAddresses, report.DateBegin, report.DateEnd,
		report.ReportID, report.RecordCount, report.ReportXML, report.CompressedReport,
		report.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to save sent report: %w", err)
	}
	return nil
}

// UpdateSentReportStatus updates the status of a sent report.
func (s *Store) UpdateSentReportStatus(ctx context.Context, id uuid.UUID, status ReportStatus, err string) error {
	query := `UPDATE dmarc_reports_sent SET status = $1, attempts = attempts + 1`
	args := []interface{}{status}
	argNum := 2

	if err != "" {
		query += fmt.Sprintf(", last_error = $%d", argNum)
		args = append(args, err)
		argNum++
	}
	if status == ReportStatusSent {
		query += fmt.Sprintf(", sent_at = $%d", argNum)
		args = append(args, time.Now())
		argNum++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argNum)
	args = append(args, id)

	_, execErr := s.pool.Exec(ctx, query, args...)
	return execErr
}

// DeleteAuthResultsForDate removes processed auth results.
func (s *Store) DeleteAuthResultsForDate(ctx context.Context, domain string, reportDate time.Time) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM dmarc_auth_results
		WHERE header_from_domain = $1 AND report_date = $2`,
		domain, reportDate,
	)
	return err
}

// GetSentReports returns sent reports with optional filtering.
func (s *Store) GetSentReports(ctx context.Context, filter ReportFilter, page, perPage int) ([]SentReport, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	query := `
		SELECT id, domain, rua_addresses, date_begin, date_end,
			   report_id, record_count, status, last_error, attempts,
			   created_at, sent_at
		FROM dmarc_reports_sent
		WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Domain != "" {
		query += fmt.Sprintf(" AND domain = $%d", argNum)
		args = append(args, filter.Domain)
		argNum++
	}
	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, filter.Status)
		argNum++
	}

	query += ` ORDER BY created_at DESC`
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, perPage, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query sent reports: %w", err)
	}
	defer rows.Close()

	var reports []SentReport
	for rows.Next() {
		var r SentReport
		err := rows.Scan(
			&r.ID, &r.Domain, &r.RUAAddresses, &r.DateBegin, &r.DateEnd,
			&r.ReportID, &r.RecordCount, &r.Status, &r.LastError, &r.Attempts,
			&r.CreatedAt, &r.SentAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan sent report: %w", err)
		}
		reports = append(reports, r)
	}

	// Get total
	countQuery := `SELECT COUNT(*) FROM dmarc_reports_sent WHERE 1=1`
	countArgs := []interface{}{}
	argNum = 1
	if filter.Domain != "" {
		countQuery += fmt.Sprintf(" AND domain = $%d", argNum)
		countArgs = append(countArgs, filter.Domain)
		argNum++
	}
	if filter.Status != "" {
		countQuery += fmt.Sprintf(" AND status = $%d", argNum)
		countArgs = append(countArgs, filter.Status)
	}

	var total int
	s.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)

	return reports, total, nil
}
