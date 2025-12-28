package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/tlsrpt"
)

// TLS-RPT Report handlers

func (s *Server) handleListTLSRPTReportsReceived(w http.ResponseWriter, r *http.Request) {
	if s.tlsrptStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "TLS-RPT reporting not configured")
		return
	}

	filter := tlsrpt.ReportFilter{
		Domain: r.URL.Query().Get("domain"),
	}

	if dateFrom := r.URL.Query().Get("date_from"); dateFrom != "" {
		if t, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			filter.DateFrom = t
		}
	}
	if dateTo := r.URL.Query().Get("date_to"); dateTo != "" {
		if t, err := time.Parse(time.RFC3339, dateTo); err == nil {
			filter.DateTo = t
		}
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	reports, total, err := s.tlsrptStore.GetReceivedReports(r.Context(), filter, page, perPage)
	if err != nil {
		s.logger.Error("failed to get TLS-RPT reports", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get reports")
		return
	}

	respondJSONWithMeta(w, http.StatusOK, reports, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (s *Server) handleGetTLSRPTReportReceived(w http.ResponseWriter, r *http.Request) {
	if s.tlsrptStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "TLS-RPT reporting not configured")
		return
	}

	reportID, err := uuid.Parse(chi.URLParam(r, "reportID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid report ID")
		return
	}

	report, err := s.tlsrptStore.GetReceivedReportByID(r.Context(), reportID)
	if err != nil {
		s.logger.Error("failed to get TLS-RPT report", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get report")
		return
	}

	if report == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	respondJSON(w, http.StatusOK, report)
}

func (s *Server) handleListTLSRPTReportsSent(w http.ResponseWriter, r *http.Request) {
	if s.tlsrptStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "TLS-RPT reporting not configured")
		return
	}

	filter := tlsrpt.ReportFilter{
		Domain: r.URL.Query().Get("domain"),
		Status: r.URL.Query().Get("status"),
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	reports, total, err := s.tlsrptStore.GetSentReports(r.Context(), filter, page, perPage)
	if err != nil {
		s.logger.Error("failed to get sent TLS-RPT reports", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get reports")
		return
	}

	respondJSONWithMeta(w, http.StatusOK, reports, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (s *Server) handleGetTLSStats(w http.ResponseWriter, r *http.Request) {
	if s.tlsrptStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "TLS-RPT reporting not configured")
		return
	}

	// Default to last 7 days
	end := time.Now().UTC()
	start := end.Add(-7 * 24 * time.Hour)

	if dateFrom := r.URL.Query().Get("date_from"); dateFrom != "" {
		if t, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			start = t
		}
	}
	if dateTo := r.URL.Query().Get("date_to"); dateTo != "" {
		if t, err := time.Parse(time.RFC3339, dateTo); err == nil {
			end = t
		}
	}

	stats, err := s.tlsrptStore.GetTLSStats(r.Context(), start, end)
	if err != nil {
		s.logger.Error("failed to get TLS stats", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get stats")
		return
	}

	respondJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetTLSStatsDomain(w http.ResponseWriter, r *http.Request) {
	if s.tlsrptStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "TLS-RPT reporting not configured")
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "INVALID_DOMAIN", "domain is required")
		return
	}

	// Default to last 7 days
	end := time.Now().UTC()
	start := end.Add(-7 * 24 * time.Hour)

	if dateFrom := r.URL.Query().Get("date_from"); dateFrom != "" {
		if t, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			start = t
		}
	}
	if dateTo := r.URL.Query().Get("date_to"); dateTo != "" {
		if t, err := time.Parse(time.RFC3339, dateTo); err == nil {
			end = t
		}
	}

	results, err := s.tlsrptStore.GetResultsForDomain(r.Context(), domain, start, end)
	if err != nil {
		s.logger.Error("failed to get TLS results for domain", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get results")
		return
	}

	// Calculate stats
	stats := struct {
		Domain      string         `json:"domain"`
		PeriodStart time.Time      `json:"period_start"`
		PeriodEnd   time.Time      `json:"period_end"`
		Total       int            `json:"total"`
		Successful  int            `json:"successful"`
		Failed      int            `json:"failed"`
		SuccessRate float64        `json:"success_rate"`
		ByResult    map[string]int `json:"by_result_type"`
	}{
		Domain:      domain,
		PeriodStart: start,
		PeriodEnd:   end,
		Total:       len(results),
		ByResult:    make(map[string]int),
	}

	for _, r := range results {
		if r.Success {
			stats.Successful++
		} else {
			stats.Failed++
		}
		stats.ByResult[r.ResultType]++
	}

	if stats.Total > 0 {
		stats.SuccessRate = float64(stats.Successful) / float64(stats.Total) * 100
	}

	respondJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetMTASTSPolicies(w http.ResponseWriter, r *http.Request) {
	if s.mtastsManager == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "MTA-STS not configured")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	policies, total, err := s.mtastsManager.GetCachedPolicies(r.Context(), page, perPage)
	if err != nil {
		s.logger.Error("failed to get MTA-STS policies", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get policies")
		return
	}

	respondJSONWithMeta(w, http.StatusOK, policies, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (s *Server) handleGetMTASTSPolicy(w http.ResponseWriter, r *http.Request) {
	if s.mtastsManager == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "MTA-STS not configured")
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "INVALID_DOMAIN", "domain is required")
		return
	}

	policy, err := s.mtastsManager.GetPolicy(r.Context(), domain)
	if err != nil {
		s.logger.Error("failed to get MTA-STS policy", "error", err)
		respondError(w, http.StatusInternalServerError, "FETCH_ERROR", "failed to get policy")
		return
	}

	if policy == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"domain":     domain,
			"has_policy": false,
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"domain":     domain,
		"has_policy": true,
		"policy":     policy,
	})
}

func (s *Server) handleRefreshMTASTSPolicy(w http.ResponseWriter, r *http.Request) {
	if s.mtastsManager == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "MTA-STS not configured")
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "INVALID_DOMAIN", "domain is required")
		return
	}

	policy, err := s.mtastsManager.RefreshPolicy(r.Context(), domain)
	if err != nil {
		s.logger.Error("failed to refresh MTA-STS policy", "error", err)
		respondError(w, http.StatusInternalServerError, "FETCH_ERROR", "failed to refresh policy")
		return
	}

	if policy == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"domain":     domain,
			"has_policy": false,
			"refreshed":  true,
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"domain":     domain,
		"has_policy": true,
		"refreshed":  true,
		"policy":     policy,
	})
}
