package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"

	"archive/zip"
)

// Parser handles DMARC aggregate report parsing from various formats.
type Parser struct {
	logger *slog.Logger
}

// NewParser creates a new DMARC report parser.
func NewParser(logger *slog.Logger) *Parser {
	return &Parser{
		logger: logger.With("component", "dmarc.parser"),
	}
}

// Parse parses a DMARC aggregate report from XML data.
func (p *Parser) Parse(data []byte) (*AggregateReport, error) {
	var report AggregateReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	// Validate required fields
	if report.ReportMetadata.OrgName == "" {
		return nil, fmt.Errorf("missing required field: org_name")
	}
	if report.ReportMetadata.ReportID == "" {
		return nil, fmt.Errorf("missing required field: report_id")
	}
	if report.PolicyPublished.Domain == "" {
		return nil, fmt.Errorf("missing required field: policy_published.domain")
	}

	return &report, nil
}

// ParseFromReader parses a DMARC report from a reader.
func (p *Parser) ParseFromReader(r io.Reader) (*AggregateReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return p.Parse(data)
}

// ParseFromGzip parses a DMARC report from gzip-compressed XML.
func (p *Parser) ParseFromGzip(data []byte) (*AggregateReport, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	xmlData, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	return p.Parse(xmlData)
}

// ParseFromZip parses a DMARC report from a ZIP archive.
func (p *Parser) ParseFromZip(data []byte) (*AggregateReport, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	// Find the XML file in the archive
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open file in zip: %w", err)
			}
			defer rc.Close()

			xmlData, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read file from zip: %w", err)
			}

			return p.Parse(xmlData)
		}
	}

	return nil, fmt.Errorf("no XML file found in zip archive")
}

// ParseFromMIME extracts and parses a DMARC report from a MIME message.
func (p *Parser) ParseFromMIME(messageData []byte) (*AggregateReport, string, error) {
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

	// Handle direct attachments
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read message body: %w", err)
	}

	return p.parseAttachment(body, mediaType, "")
}

// parseMultipart handles multipart MIME messages.
func (p *Parser) parseMultipart(body io.Reader, boundary string) (*AggregateReport, string, error) {
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

		// Check for DMARC report content types
		if p.isReportContentType(mediaType) || p.isReportFilename(part.FileName()) {
			data, err := io.ReadAll(part)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read part: %w", err)
			}

			report, rawXML, err := p.parseAttachment(data, mediaType, part.FileName())
			if err == nil {
				return report, rawXML, nil
			}
			p.logger.Debug("failed to parse attachment", "filename", part.FileName(), "error", err)
		}
	}

	return nil, "", fmt.Errorf("no DMARC report found in multipart message")
}

// parseAttachment parses a DMARC report from an attachment.
func (p *Parser) parseAttachment(data []byte, mediaType, filename string) (*AggregateReport, string, error) {
	var xmlData []byte
	var err error

	// Determine format based on content type or filename
	switch {
	case mediaType == "application/gzip" ||
		mediaType == "application/x-gzip" ||
		strings.HasSuffix(strings.ToLower(filename), ".gz"):
		xmlData, err = p.decompressGzip(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decompress gzip: %w", err)
		}

	case mediaType == "application/zip" ||
		mediaType == "application/x-zip-compressed" ||
		strings.HasSuffix(strings.ToLower(filename), ".zip"):
		xmlData, err = p.extractFromZip(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to extract from zip: %w", err)
		}

	case mediaType == "text/xml" ||
		mediaType == "application/xml" ||
		strings.HasSuffix(strings.ToLower(filename), ".xml"):
		xmlData = data

	default:
		// Try to auto-detect format
		xmlData, err = p.autoDetectAndParse(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to auto-detect format: %w", err)
		}
	}

	report, err := p.Parse(xmlData)
	if err != nil {
		return nil, "", err
	}

	return report, string(xmlData), nil
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

// extractFromZip extracts XML from a ZIP archive.
func (p *Parser) extractFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("no XML file found in zip")
}

// autoDetectAndParse tries to auto-detect the format and parse.
func (p *Parser) autoDetectAndParse(data []byte) ([]byte, error) {
	// Check for gzip magic bytes
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return p.decompressGzip(data)
	}

	// Check for ZIP magic bytes
	if len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04 {
		return p.extractFromZip(data)
	}

	// Check if it looks like XML
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '<' || bytes.HasPrefix(trimmed, []byte("<?xml"))) {
		return data, nil
	}

	return nil, fmt.Errorf("unable to detect format")
}

// IsReport checks if a message appears to be a DMARC aggregate report.
func (p *Parser) IsReport(contentType, subject, fromAddress string) bool {
	// Check content type
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil && p.isReportContentType(mediaType) {
			return true
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

// isReportContentType checks if the content type indicates a DMARC report.
func (p *Parser) isReportContentType(mediaType string) bool {
	reportTypes := []string{
		"application/gzip",
		"application/x-gzip",
		"application/zip",
		"application/x-zip-compressed",
	}

	mediaType = strings.ToLower(mediaType)
	for _, rt := range reportTypes {
		if mediaType == rt {
			return true
		}
	}

	return false
}

// isReportFilename checks if the filename indicates a DMARC report.
func (p *Parser) isReportFilename(filename string) bool {
	filename = strings.ToLower(filename)

	// DMARC report filenames typically follow pattern:
	// receiver!policy-domain!begin-timestamp!end-timestamp.xml.gz
	// or similar patterns
	patterns := []string{
		".xml.gz",
		".xml.zip",
		"dmarc",
	}

	for _, pattern := range patterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}

	return false
}

// isReportSubject checks if the subject line indicates a DMARC report.
func (p *Parser) isReportSubject(subject string) bool {
	subject = strings.ToLower(subject)

	// Common DMARC report subject patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`report domain:\s*\S+.*submitter:\s*\S+`),
		regexp.MustCompile(`dmarc.*aggregate.*report`),
		regexp.MustCompile(`^report-id:\s*`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(subject) {
			return true
		}
	}

	// Check for common keywords
	keywords := []string{
		"dmarc aggregate",
		"dmarc report",
		"report domain:",
	}

	for _, kw := range keywords {
		if strings.Contains(subject, kw) {
			return true
		}
	}

	return false
}

// isReportSender checks if the sender address indicates a DMARC report source.
func (p *Parser) isReportSender(fromAddress string) bool {
	fromAddress = strings.ToLower(fromAddress)

	// Common DMARC report sender patterns
	patterns := []string{
		"noreply-dmarc",
		"dmarc-noreply",
		"dmarc_report",
		"dmarc-report",
		"postmaster",
		"mailer-daemon",
	}

	for _, pattern := range patterns {
		if strings.Contains(fromAddress, pattern) {
			return true
		}
	}

	return false
}

// CountResults counts pass/fail records in a report.
func (p *Parser) CountResults(report *AggregateReport) (passCount, failCount int) {
	for _, record := range report.Records {
		if record.Row.PolicyEvaluated.DKIM == "pass" || record.Row.PolicyEvaluated.SPF == "pass" {
			passCount += record.Row.Count
		} else {
			failCount += record.Row.Count
		}
	}
	return
}
