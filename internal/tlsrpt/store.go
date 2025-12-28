package tlsrpt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles TLS-RPT database operations.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewStore creates a new TLS-RPT store.
func NewStore(pool *pgxpool.Pool, logger *slog.Logger) *Store {
	return &Store{
		pool:   pool,
		logger: logger.With("component", "tlsrpt.store"),
	}
}

// SaveConnectionResult stores a TLS connection result.
func (s *Store) SaveConnectionResult(ctx context.Context, result *ConnectionResult) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tls_connection_results (
			id, queue_id, recipient_domain, mx_host, mx_ip,
			result_type, success, policy_type, policy_domain, policy_string,
			failure_reason_code, failure_reason_text, sending_mta_ip,
			receiving_ip, receiving_mx_hostname, receiving_mx_helo,
			tls_version, cipher_suite, cert_issuer, cert_subject, cert_expiry,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
		result.ID, result.QueueID, result.RecipientDomain, result.MXHost, result.MXIP,
		result.ResultType, result.Success, result.PolicyType, result.PolicyDomain, result.PolicyString,
		result.FailureReasonCode, result.FailureReasonText, result.SendingMTAIP,
		result.ReceivingIP, result.ReceivingMXHostname, result.ReceivingMXHelo,
		result.TLSVersion, result.CipherSuite, result.CertIssuer, result.CertSubject, result.CertExpiry,
		result.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save connection result: %w", err)
	}
	return nil
}

// GetConnectionResults retrieves connection results with filtering.
func (s *Store) GetConnectionResults(ctx context.Context, filter ReportFilter, page, perPage int) ([]ConnectionResult, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	query := `
		SELECT id, queue_id, recipient_domain, mx_host, mx_ip,
			   result_type, success, policy_type, policy_domain, policy_string,
			   failure_reason_code, failure_reason_text, sending_mta_ip,
			   receiving_ip, receiving_mx_hostname, receiving_mx_helo,
			   tls_version, cipher_suite, cert_issuer, cert_subject, cert_expiry,
			   created_at
		FROM tls_connection_results
		WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Domain != "" {
		query += fmt.Sprintf(" AND recipient_domain = $%d", argNum)
		args = append(args, filter.Domain)
		argNum++
	}
	if !filter.DateFrom.IsZero() {
		query += fmt.Sprintf(" AND created_at >= $%d", argNum)
		args = append(args, filter.DateFrom)
		argNum++
	}
	if !filter.DateTo.IsZero() {
		query += fmt.Sprintf(" AND created_at <= $%d", argNum)
		args = append(args, filter.DateTo)
		argNum++
	}

	query += ` ORDER BY created_at DESC`
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, perPage, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query results: %w", err)
	}
	defer rows.Close()

	var results []ConnectionResult
	for rows.Next() {
		var r ConnectionResult
		err := rows.Scan(
			&r.ID, &r.QueueID, &r.RecipientDomain, &r.MXHost, &r.MXIP,
			&r.ResultType, &r.Success, &r.PolicyType, &r.PolicyDomain, &r.PolicyString,
			&r.FailureReasonCode, &r.FailureReasonText, &r.SendingMTAIP,
			&r.ReceivingIP, &r.ReceivingMXHostname, &r.ReceivingMXHelo,
			&r.TLSVersion, &r.CipherSuite, &r.CertIssuer, &r.CertSubject, &r.CertExpiry,
			&r.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan result: %w", err)
		}
		results = append(results, r)
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM tls_connection_results WHERE 1=1`
	s.pool.QueryRow(ctx, countQuery).Scan(&total)

	return results, total, nil
}

// SaveReceivedReport stores a received TLS-RPT report.
func (s *Store) SaveReceivedReport(ctx context.Context, report *Report, policyDomain string) (*ReceivedReport, error) {
	rawJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	// Calculate totals
	var totalSuccess, totalFailed int
	for _, p := range report.Policies {
		totalSuccess += p.Summary.TotalSuccessfulSessionCount
		totalFailed += p.Summary.TotalFailureSessionCount
	}

	var id uuid.UUID
	now := time.Now()
	err = s.pool.QueryRow(ctx, `
		INSERT INTO tlsrpt_reports_received (
			organization_name, report_id, contact_info,
			date_range_start, date_range_end, policy_domain,
			raw_report, total_successful, total_failed,
			received_at, processed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (organization_name, report_id) DO UPDATE SET
			received_at = EXCLUDED.received_at
		RETURNING id`,
		report.OrganizationName, report.ReportID, report.ContactInfo,
		report.DateRange.StartDateTime, report.DateRange.EndDateTime, policyDomain,
		rawJSON, totalSuccess, totalFailed,
		now, now,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("failed to save received report: %w", err)
	}

	return &ReceivedReport{
		ID:               id,
		OrganizationName: report.OrganizationName,
		ReportID:         report.ReportID,
		DateRangeStart:   report.DateRange.StartDateTime,
		DateRangeEnd:     report.DateRange.EndDateTime,
		PolicyDomain:     policyDomain,
		TotalSuccessful:  totalSuccess,
		TotalFailed:      totalFailed,
		ReceivedAt:       now,
	}, nil
}

// GetReceivedReports retrieves received reports with filtering.
func (s *Store) GetReceivedReports(ctx context.Context, filter ReportFilter, page, perPage int) ([]ReceivedReport, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	query := `
		SELECT id, organization_name, report_id, contact_info,
			   date_range_start, date_range_end, policy_domain,
			   total_successful, total_failed, received_at, processed_at, created_at
		FROM tlsrpt_reports_received
		WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Domain != "" {
		query += fmt.Sprintf(" AND policy_domain = $%d", argNum)
		args = append(args, filter.Domain)
		argNum++
	}
	if !filter.DateFrom.IsZero() {
		query += fmt.Sprintf(" AND date_range_start >= $%d", argNum)
		args = append(args, filter.DateFrom)
		argNum++
	}
	if !filter.DateTo.IsZero() {
		query += fmt.Sprintf(" AND date_range_end <= $%d", argNum)
		args = append(args, filter.DateTo)
		argNum++
	}

	query += ` ORDER BY received_at DESC`
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
			&r.ID, &r.OrganizationName, &r.ReportID, &r.ContactInfo,
			&r.DateRangeStart, &r.DateRangeEnd, &r.PolicyDomain,
			&r.TotalSuccessful, &r.TotalFailed, &r.ReceivedAt, &r.ProcessedAt, &r.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan report: %w", err)
		}
		reports = append(reports, r)
	}

	var total int
	s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tlsrpt_reports_received`).Scan(&total)

	return reports, total, nil
}

// GetReceivedReportByID returns a single received report with full details.
func (s *Store) GetReceivedReportByID(ctx context.Context, id uuid.UUID) (*ReceivedReport, error) {
	var r ReceivedReport
	var rawJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_name, report_id, contact_info,
			   date_range_start, date_range_end, policy_domain,
			   raw_report, total_successful, total_failed,
			   received_at, processed_at, created_at
		FROM tlsrpt_reports_received
		WHERE id = $1`, id,
	).Scan(
		&r.ID, &r.OrganizationName, &r.ReportID, &r.ContactInfo,
		&r.DateRangeStart, &r.DateRangeEnd, &r.PolicyDomain,
		&rawJSON, &r.TotalSuccessful, &r.TotalFailed,
		&r.ReceivedAt, &r.ProcessedAt, &r.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	if len(rawJSON) > 0 {
		var report Report
		json.Unmarshal(rawJSON, &report)
		r.RawReport = &report
	}

	return &r, nil
}

// GetTLSStats returns TLS connection statistics.
func (s *Store) GetTLSStats(ctx context.Context, start, end time.Time) (*TLSStats, error) {
	stats := &TLSStats{
		Period:       fmt.Sprintf("%s to %s", start.Format("2006-01-02"), end.Format("2006-01-02")),
		ByResultType: make(map[string]int),
		ByPolicyType: make(map[string]int),
	}

	// Get overall counts
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN success THEN 1 ELSE 0 END), 0) as successful,
			COALESCE(SUM(CASE WHEN NOT success THEN 1 ELSE 0 END), 0) as failed
		FROM tls_connection_results
		WHERE created_at >= $1 AND created_at <= $2`,
		start, end,
	).Scan(&stats.TotalConnections, &stats.Successful, &stats.Failed)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	if stats.TotalConnections > 0 {
		stats.SuccessRate = float64(stats.Successful) / float64(stats.TotalConnections) * 100
	}

	// Get counts by result type
	rows, err := s.pool.Query(ctx, `
		SELECT result_type, COUNT(*) as count
		FROM tls_connection_results
		WHERE created_at >= $1 AND created_at <= $2
		GROUP BY result_type
		ORDER BY count DESC`,
		start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get result type stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var resultType string
		var count int
		if err := rows.Scan(&resultType, &count); err != nil {
			continue
		}
		stats.ByResultType[resultType] = count
	}

	// Get counts by policy type
	rows, err = s.pool.Query(ctx, `
		SELECT policy_type, COUNT(*) as count
		FROM tls_connection_results
		WHERE created_at >= $1 AND created_at <= $2
		GROUP BY policy_type
		ORDER BY count DESC`,
		start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy type stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var policyType string
		var count int
		if err := rows.Scan(&policyType, &count); err != nil {
			continue
		}
		stats.ByPolicyType[policyType] = count
	}

	// Get top failing domains
	rows, err = s.pool.Query(ctx, `
		SELECT recipient_domain,
			   COUNT(*) as total,
			   SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
			   SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed
		FROM tls_connection_results
		WHERE created_at >= $1 AND created_at <= $2
		GROUP BY recipient_domain
		HAVING SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) > 0
		ORDER BY failed DESC
		LIMIT 10`,
		start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ds DomainStats
		if err := rows.Scan(&ds.Domain, &ds.Total, &ds.Successful, &ds.Failed); err != nil {
			continue
		}
		if ds.Total > 0 {
			ds.FailRate = float64(ds.Failed) / float64(ds.Total) * 100
		}
		stats.TopFailingDomains = append(stats.TopFailingDomains, ds)
	}

	return stats, nil
}

// GetDomainsWithResults returns domains that have TLS results for a date.
func (s *Store) GetDomainsWithResults(ctx context.Context, date time.Time) ([]string, error) {
	start := date.Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)

	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT recipient_domain
		FROM tls_connection_results
		WHERE created_at >= $1 AND created_at < $2
		ORDER BY recipient_domain`,
		start, end,
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

// GetResultsForDomain retrieves results for report generation.
func (s *Store) GetResultsForDomain(ctx context.Context, domain string, start, end time.Time) ([]ConnectionResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, queue_id, recipient_domain, mx_host, mx_ip,
			   result_type, success, policy_type, policy_domain, policy_string,
			   failure_reason_code, failure_reason_text, sending_mta_ip,
			   receiving_ip, receiving_mx_hostname, receiving_mx_helo,
			   tls_version, cipher_suite, cert_issuer, cert_subject, cert_expiry,
			   created_at
		FROM tls_connection_results
		WHERE recipient_domain = $1 AND created_at >= $2 AND created_at < $3
		ORDER BY created_at`,
		domain, start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}
	defer rows.Close()

	var results []ConnectionResult
	for rows.Next() {
		var r ConnectionResult
		err := rows.Scan(
			&r.ID, &r.QueueID, &r.RecipientDomain, &r.MXHost, &r.MXIP,
			&r.ResultType, &r.Success, &r.PolicyType, &r.PolicyDomain, &r.PolicyString,
			&r.FailureReasonCode, &r.FailureReasonText, &r.SendingMTAIP,
			&r.ReceivingIP, &r.ReceivingMXHostname, &r.ReceivingMXHelo,
			&r.TLSVersion, &r.CipherSuite, &r.CertIssuer, &r.CertSubject, &r.CertExpiry,
			&r.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan result: %w", err)
		}
		results = append(results, r)
	}

	return results, nil
}

// SaveSentReport stores an outbound TLS-RPT report.
func (s *Store) SaveSentReport(ctx context.Context, report *SentReport) error {
	policiesJSON, _ := json.Marshal(report.Policies)
	reportJSON, _ := json.Marshal(report.ReportJSON)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO tlsrpt_reports_sent (
			id, report_id, date_range_start, date_range_end,
			policy_domain, rua_uri, policies, report_json, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		report.ID, report.ReportID, report.DateRangeStart, report.DateRangeEnd,
		report.PolicyDomain, report.RUAURI, policiesJSON, reportJSON, report.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to save sent report: %w", err)
	}
	return nil
}

// UpdateSentReportStatus updates the status of a sent report.
func (s *Store) UpdateSentReportStatus(ctx context.Context, id uuid.UUID, status, errMsg string) error {
	query := `UPDATE tlsrpt_reports_sent SET status = $1, retry_count = retry_count + 1`
	args := []interface{}{status}
	argNum := 2

	if errMsg != "" {
		query += fmt.Sprintf(", error = $%d", argNum)
		args = append(args, errMsg)
		argNum++
	}
	if status == ReportStatusSent {
		query += fmt.Sprintf(", sent_at = $%d", argNum)
		args = append(args, time.Now())
		argNum++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argNum)
	args = append(args, id)

	_, err := s.pool.Exec(ctx, query, args...)
	return err
}

// GetSentReports retrieves sent reports with filtering.
func (s *Store) GetSentReports(ctx context.Context, filter ReportFilter, page, perPage int) ([]SentReport, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	query := `
		SELECT id, report_id, date_range_start, date_range_end,
			   policy_domain, rua_uri, status, sent_at, error, retry_count, created_at
		FROM tlsrpt_reports_sent
		WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Domain != "" {
		query += fmt.Sprintf(" AND policy_domain = $%d", argNum)
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
			&r.ID, &r.ReportID, &r.DateRangeStart, &r.DateRangeEnd,
			&r.PolicyDomain, &r.RUAURI, &r.Status, &r.SentAt, &r.Error, &r.RetryCount, &r.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan sent report: %w", err)
		}
		reports = append(reports, r)
	}

	var total int
	s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tlsrpt_reports_sent`).Scan(&total)

	return reports, total, nil
}

// DeleteOldResults removes old connection results.
func (s *Store) DeleteOldResults(ctx context.Context, before time.Time) (int, error) {
	result, err := s.pool.Exec(ctx, `
		DELETE FROM tls_connection_results
		WHERE created_at < $1`,
		before,
	)
	if err != nil {
		return 0, err
	}
	return int(result.RowsAffected()), nil
}
