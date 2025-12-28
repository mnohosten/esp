package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/dmarc"
)

// DMARC Report handlers

func (s *Server) handleListDMARCReportsReceived(w http.ResponseWriter, r *http.Request) {
	if s.dmarcStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "DMARC reporting not configured")
		return
	}

	filter := dmarc.ReportFilter{
		Domain:  r.URL.Query().Get("domain"),
		OrgName: r.URL.Query().Get("org_name"),
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

	reports, total, err := s.dmarcStore.GetReceivedReports(r.Context(), filter, page, perPage)
	if err != nil {
		s.logger.Error("failed to get DMARC reports", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get reports")
		return
	}

	respondJSONWithMeta(w, http.StatusOK, reports, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (s *Server) handleGetDMARCReportReceived(w http.ResponseWriter, r *http.Request) {
	if s.dmarcStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "DMARC reporting not configured")
		return
	}

	reportID, err := uuid.Parse(chi.URLParam(r, "reportID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid report ID")
		return
	}

	report, records, err := s.dmarcStore.GetReceivedReportByID(r.Context(), reportID)
	if err != nil {
		s.logger.Error("failed to get DMARC report", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get report")
		return
	}

	if report == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"report":  report,
		"records": records,
	})
}

func (s *Server) handleListDMARCReportsSent(w http.ResponseWriter, r *http.Request) {
	if s.dmarcStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "DMARC reporting not configured")
		return
	}

	filter := dmarc.ReportFilter{
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

	reports, total, err := s.dmarcStore.GetSentReports(r.Context(), filter, page, perPage)
	if err != nil {
		s.logger.Error("failed to get sent DMARC reports", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get reports")
		return
	}

	respondJSONWithMeta(w, http.StatusOK, reports, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (s *Server) handleGetDMARCStats(w http.ResponseWriter, r *http.Request) {
	if s.dmarcStore == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "DMARC reporting not configured")
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "INVALID_DOMAIN", "domain is required")
		return
	}

	// Default to last 30 days
	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)

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

	stats, err := s.dmarcStore.GetDomainStats(r.Context(), domain, start, end)
	if err != nil {
		s.logger.Error("failed to get DMARC stats", "error", err)
		respondError(w, http.StatusInternalServerError, "DATABASE_ERROR", "failed to get stats")
		return
	}

	respondJSON(w, http.StatusOK, stats)
}

// DMARCReportResponse wraps a DMARC report for API response
type DMARCReportResponse struct {
	Report  *dmarc.ReceivedReport `json:"report"`
	Records []dmarc.ReportRecord  `json:"records,omitempty"`
}

// DMARCStatsRequest for stats queries
type DMARCStatsRequest struct {
	Domain   string    `json:"domain" validate:"required"`
	DateFrom time.Time `json:"date_from"`
	DateTo   time.Time `json:"date_to"`
}
