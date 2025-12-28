package mtasts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Fetcher handles fetching MTA-STS policies from remote domains.
type Fetcher struct {
	httpClient *http.Client
	logger     *slog.Logger
}

// FetcherConfig contains configuration for the fetcher.
type FetcherConfig struct {
	Timeout time.Duration
}

// NewFetcher creates a new MTA-STS policy fetcher.
func NewFetcher(logger *slog.Logger, config FetcherConfig) *Fetcher {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &Fetcher{
		httpClient: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// MTA-STS requires no redirects to different hosts
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("redirect to different host not allowed")
				}
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		logger: logger.With("component", "mtasts.fetcher"),
	}
}

// Fetch retrieves the MTA-STS policy for a domain.
func (f *Fetcher) Fetch(ctx context.Context, domain string) (*FetchResult, error) {
	result := &FetchResult{
		FetchedAt: time.Now(),
	}

	// Step 1: Look up _mta-sts.domain TXT record
	dnsRecord, err := f.lookupDNSRecord(ctx, domain)
	if err != nil {
		result.Error = err
		result.DNSError = true
		if isNotFoundError(err) {
			result.NotFound = true
		}
		return result, nil
	}

	result.PolicyID = dnsRecord.ID

	// Step 2: Fetch policy from https://mta-sts.domain/.well-known/mta-sts.txt
	policy, err := f.fetchPolicy(ctx, domain)
	if err != nil {
		result.Error = err
		result.HTTPError = true
		return result, nil
	}

	result.Policy = policy
	return result, nil
}

// lookupDNSRecord looks up the MTA-STS DNS TXT record.
func (f *Fetcher) lookupDNSRecord(ctx context.Context, domain string) (*DNSRecord, error) {
	recordDomain := "_mta-sts." + domain

	records, err := net.DefaultResolver.LookupTXT(ctx, recordDomain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	for _, record := range records {
		// MTA-STS record format: v=STSv1; id=20190429T010101
		record = strings.TrimSpace(record)
		if !strings.HasPrefix(strings.ToLower(record), "v=stsv1") {
			continue
		}

		dnsRecord := &DNSRecord{
			RawValue: record,
		}

		parts := strings.Split(record, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}

			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.TrimSpace(kv[1])

			switch key {
			case "v":
				dnsRecord.Version = value
			case "id":
				dnsRecord.ID = value
			}
		}

		if dnsRecord.Version != "" && dnsRecord.ID != "" {
			return dnsRecord, nil
		}
	}

	return nil, fmt.Errorf("no valid MTA-STS DNS record found")
}

// fetchPolicy fetches the policy file via HTTPS.
func (f *Fetcher) fetchPolicy(ctx context.Context, domain string) (*Policy, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Verify content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		f.logger.Warn("unexpected content type for MTA-STS policy",
			"domain", domain,
			"content_type", contentType,
		)
	}

	// Read and parse policy (limit to 64KB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return f.parsePolicy(string(body))
}

// parsePolicy parses the MTA-STS policy file content.
func (f *Fetcher) parsePolicy(content string) (*Policy, error) {
	policy := &Policy{}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "version":
			policy.Version = value
		case "mode":
			policy.Mode = strings.ToLower(value)
		case "mx":
			policy.MX = append(policy.MX, value)
		case "max_age":
			maxAge, err := strconv.Atoi(value)
			if err == nil {
				policy.MaxAge = maxAge
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Validate required fields
	if policy.Version != "STSv1" {
		return nil, fmt.Errorf("invalid or missing version: %s", policy.Version)
	}
	if policy.Mode == "" {
		return nil, fmt.Errorf("missing mode")
	}
	if policy.Mode != "enforce" && policy.Mode != "testing" && policy.Mode != "none" {
		return nil, fmt.Errorf("invalid mode: %s", policy.Mode)
	}
	if len(policy.MX) == 0 && policy.Mode != "none" {
		return nil, fmt.Errorf("missing MX patterns")
	}
	if policy.MaxAge <= 0 {
		return nil, fmt.Errorf("invalid or missing max_age")
	}

	return policy, nil
}

// isNotFoundError checks if the error indicates the record doesn't exist.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "nxdomain")
}
