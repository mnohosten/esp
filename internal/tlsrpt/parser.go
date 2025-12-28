package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

// Parser handles TLS-RPT report parsing.
type Parser struct {
	logger *slog.Logger
}

// NewParser creates a new TLS-RPT report parser.
func NewParser(logger *slog.Logger) *Parser {
	return &Parser{
		logger: logger.With("component", "tlsrpt.parser"),
	}
}

// Parse parses a TLS-RPT report from JSON data.
func (p *Parser) Parse(data []byte) (*Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if report.OrganizationName == "" {
		return nil, fmt.Errorf("missing required field: organization-name")
	}
	if report.ReportID == "" {
		return nil, fmt.Errorf("missing required field: report-id")
	}
	if len(report.Policies) == 0 {
		return nil, fmt.Errorf("missing required field: policies")
	}

	return &report, nil
}

// ParseFromReader parses a TLS-RPT report from a reader.
func (p *Parser) ParseFromReader(r io.Reader) (*Report, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return p.Parse(data)
}

// ParseFromGzip parses a TLS-RPT report from gzip-compressed JSON.
func (p *Parser) ParseFromGzip(data []byte) (*Report, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	jsonData, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	return p.Parse(jsonData)
}

// ParseFromMIME extracts and parses a TLS-RPT report from a MIME message.
func (p *Parser) ParseFromMIME(messageData []byte) (*Report, string, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(messageData))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse MIME message: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse content-type: %w", err)
	}

	// Handle multipart messages
	if strings.HasPrefix(mediaType, "multipart/") {
		return p.parseMultipart(msg.Body, params["boundary"])
	}

	// Handle direct content
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read message body: %w", err)
	}

	return p.parseAttachment(body, mediaType, "")
}

// parseMultipart handles multipart MIME messages.
func (p *Parser) parseMultipart(body io.Reader, boundary string) (*Report, string, error) {
	mr := multipart.NewReader(body, boundary)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("failed to read multipart: %w", err)
		}

		contentType := part.Header.Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			continue
		}

		// Check for TLS-RPT content types
		if p.isReportContentType(mediaType) || p.isReportFilename(part.FileName()) {
			data, err := io.ReadAll(part)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read part: %w", err)
			}

			report, policyDomain, err := p.parseAttachment(data, mediaType, part.FileName())
			if err == nil {
				return report, policyDomain, nil
			}
			p.logger.Debug("failed to parse attachment", "filename", part.FileName(), "error", err)
		}
	}

	return nil, "", fmt.Errorf("no TLS-RPT report found in multipart message")
}

// parseAttachment parses a TLS-RPT report from an attachment.
func (p *Parser) parseAttachment(data []byte, mediaType, filename string) (*Report, string, error) {
	var jsonData []byte
	var err error

	// Determine format based on content type or filename
	switch {
	case mediaType == "application/gzip" ||
		mediaType == "application/x-gzip" ||
		strings.HasSuffix(strings.ToLower(filename), ".gz"):
		jsonData, err = p.decompressGzip(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decompress gzip: %w", err)
		}

	case mediaType == "application/json" ||
		mediaType == "application/tlsrpt+json" ||
		strings.HasSuffix(strings.ToLower(filename), ".json"):
		jsonData = data

	default:
		// Try to auto-detect format
		jsonData, err = p.autoDetect(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to auto-detect format: %w", err)
		}
	}

	report, err := p.Parse(jsonData)
	if err != nil {
		return nil, "", err
	}

	// Extract policy domain from report
	var policyDomain string
	if len(report.Policies) > 0 {
		policyDomain = report.Policies[0].Policy.PolicyDomain
	}

	return report, policyDomain, nil
}

// decompressGzip decompresses gzip data.
func (p *Parser) decompressGzip(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// autoDetect tries to auto-detect the format and parse.
func (p *Parser) autoDetect(data []byte) ([]byte, error) {
	// Check for gzip magic bytes
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return p.decompressGzip(data)
	}

	// Check if it looks like JSON
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return data, nil
	}

	return nil, fmt.Errorf("unable to detect format")
}

// IsReport checks if a message appears to be a TLS-RPT report.
func (p *Parser) IsReport(contentType, subject, fromAddress string) bool {
	// Check content type for TLS-RPT specific type
	if contentType != "" {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err == nil {
			// Check for report-type parameter
			if params["report-type"] == "tlsrpt" {
				return true
			}
			if p.isReportContentType(mediaType) {
				return true
			}
		}
	}

	// Check subject line patterns
	if p.isReportSubject(subject) {
		return true
	}

	// Check from address patterns
	if p.isReportSender(fromAddress) {
		return true
	}

	return false
}

// isReportContentType checks if the content type indicates a TLS-RPT report.
func (p *Parser) isReportContentType(mediaType string) bool {
	reportTypes := []string{
		"application/tlsrpt+json",
		"application/tlsrpt+gzip",
	}

	mediaType = strings.ToLower(mediaType)
	for _, rt := range reportTypes {
		if mediaType == rt {
			return true
		}
	}

	return false
}

// isReportFilename checks if the filename indicates a TLS-RPT report.
func (p *Parser) isReportFilename(filename string) bool {
	filename = strings.ToLower(filename)
	return strings.Contains(filename, "tlsrpt") ||
		(strings.HasSuffix(filename, ".json") && strings.Contains(filename, "tls"))
}

// isReportSubject checks if the subject line indicates a TLS-RPT report.
func (p *Parser) isReportSubject(subject string) bool {
	subject = strings.ToLower(subject)
	return strings.Contains(subject, "tls-rpt") ||
		strings.Contains(subject, "tlsrpt") ||
		strings.Contains(subject, "tls report")
}

// isReportSender checks if the sender address indicates a TLS-RPT report source.
func (p *Parser) isReportSender(fromAddress string) bool {
	fromAddress = strings.ToLower(fromAddress)
	patterns := []string{
		"tlsrpt",
		"tls-report",
		"smtp-tls",
		"postmaster",
	}

	for _, pattern := range patterns {
		if strings.Contains(fromAddress, pattern) {
			return true
		}
	}

	return false
}
