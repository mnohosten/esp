package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
)

// SPFResult represents the result of an SPF check.
type SPFResult string

const (
	SPFNone      SPFResult = "none"
	SPFNeutral   SPFResult = "neutral"
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftFail  SPFResult = "softfail"
	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// DKIMResult represents the result of a DKIM verification.
type DKIMResult string

const (
	DKIMNone      DKIMResult = "none"
	DKIMPass      DKIMResult = "pass"
	DKIMFail      DKIMResult = "fail"
	DKIMTempError DKIMResult = "temperror"
	DKIMPermError DKIMResult = "permerror"
)

// DMARCResult represents the result of a DMARC check.
type DMARCResult string

const (
	DMARCNone      DMARCResult = "none"
	DMARCPass      DMARCResult = "pass"
	DMARCFail      DMARCResult = "fail"
	DMARCTempError DMARCResult = "temperror"
	DMARCPermError DMARCResult = "permerror"
)

// DMARCPolicy represents a DMARC policy action.
type DMARCPolicy string

const (
	DMARCPolicyNone       DMARCPolicy = "none"
	DMARCPolicyQuarantine DMARCPolicy = "quarantine"
	DMARCPolicyReject     DMARCPolicy = "reject"
)

// VerificationResult contains the results of all email authentication checks.
type VerificationResult struct {
	SPF   SPFResult
	DKIM  DKIMResult
	DMARC DMARCResult

	SPFDomain   string
	DKIMDomain  string
	DMARCDomain string
	DMARCPolicy DMARCPolicy

	// Details for headers
	SPFDetails   string
	DKIMDetails  string
	DMARCDetails string
}

// Verifier handles email authentication verification (SPF, DKIM, DMARC).
type Verifier struct {
	logger *slog.Logger
}

// NewVerifier creates a new email verifier.
func NewVerifier(logger *slog.Logger) *Verifier {
	return &Verifier{
		logger: logger.With("component", "smtp.verifier"),
	}
}

// VerifySPF checks the SPF record for the sender.
func (v *Verifier) VerifySPF(ctx context.Context, clientIP net.IP, helo, mailFrom string) (SPFResult, string, error) {
	v.logger.Debug("verifying SPF",
		"client_ip", clientIP.String(),
		"helo", helo,
		"mail_from", mailFrom,
	)

	result, err := spf.CheckHostWithSender(clientIP, helo, mailFrom, spf.WithContext(ctx))
	if err != nil {
		v.logger.Warn("SPF check error", "error", err)
	}

	spfResult := mapSPFResult(result)
	details := fmt.Sprintf("%s (%s)", spfResult, extractDomain(mailFrom))

	v.logger.Debug("SPF result",
		"result", spfResult,
		"domain", extractDomain(mailFrom),
	)

	return spfResult, details, nil
}

// VerifyDKIM checks the DKIM signature(s) of a message.
func (v *Verifier) VerifyDKIM(ctx context.Context, messageReader io.Reader) (DKIMResult, string, []string, error) {
	v.logger.Debug("verifying DKIM")

	verifications, err := dkim.Verify(messageReader)
	if err != nil {
		v.logger.Warn("DKIM verification error", "error", err)
		return DKIMTempError, "temporary error", nil, err
	}

	if len(verifications) == 0 {
		v.logger.Debug("no DKIM signatures found")
		return DKIMNone, "no signatures", nil, nil
	}

	var domains []string
	var passCount, failCount int

	for _, ver := range verifications {
		domain := ver.Domain
		domains = append(domains, domain)

		if ver.Err != nil {
			v.logger.Debug("DKIM signature failed",
				"domain", domain,
				"error", ver.Err,
			)
			if dkim.IsPermFail(ver.Err) {
				failCount++
			} else if dkim.IsTempFail(ver.Err) {
				return DKIMTempError, fmt.Sprintf("temporary error for %s", domain), domains, nil
			}
		} else {
			v.logger.Debug("DKIM signature passed", "domain", domain)
			passCount++
		}
	}

	if passCount > 0 {
		return DKIMPass, fmt.Sprintf("pass (%d of %d signatures)", passCount, len(verifications)), domains, nil
	}

	if failCount > 0 {
		return DKIMFail, fmt.Sprintf("fail (%d signatures failed)", failCount), domains, nil
	}

	return DKIMPermError, "permanent error", domains, nil
}

// VerifyDMARC checks the DMARC policy for the From domain.
func (v *Verifier) VerifyDMARC(ctx context.Context, fromDomain string, spfResult SPFResult, spfDomain string, dkimResult DKIMResult, dkimDomains []string) (DMARCResult, DMARCPolicy, string, error) {
	v.logger.Debug("verifying DMARC", "from_domain", fromDomain)

	record, err := dmarc.Lookup(fromDomain)
	if err != nil {
		if err == dmarc.ErrNoPolicy {
			v.logger.Debug("no DMARC policy found", "domain", fromDomain)
			return DMARCNone, DMARCPolicyNone, "no policy", nil
		}
		if dmarc.IsTempFail(err) {
			v.logger.Warn("DMARC lookup temporary failure", "error", err)
			return DMARCTempError, DMARCPolicyNone, "temporary error", err
		}
		v.logger.Warn("DMARC lookup error", "error", err)
		return DMARCPermError, DMARCPolicyNone, "lookup error", err
	}

	// Check SPF alignment
	spfAligned := false
	if spfResult == SPFPass {
		spfAligned = checkAlignment(fromDomain, spfDomain, record.SPFAlignment)
	}

	// Check DKIM alignment
	dkimAligned := false
	if dkimResult == DKIMPass {
		for _, dkimDomain := range dkimDomains {
			if checkAlignment(fromDomain, dkimDomain, record.DKIMAlignment) {
				dkimAligned = true
				break
			}
		}
	}

	// DMARC passes if either SPF or DKIM is aligned
	policy := mapDMARCPolicy(record.Policy)
	if spfAligned || dkimAligned {
		v.logger.Debug("DMARC passed",
			"spf_aligned", spfAligned,
			"dkim_aligned", dkimAligned,
		)
		return DMARCPass, policy, fmt.Sprintf("pass (policy=%s)", policy), nil
	}

	v.logger.Debug("DMARC failed",
		"spf_aligned", spfAligned,
		"dkim_aligned", dkimAligned,
		"policy", policy,
	)
	return DMARCFail, policy, fmt.Sprintf("fail (policy=%s)", policy), nil
}

// Verify performs all verification checks and returns a combined result.
func (v *Verifier) Verify(ctx context.Context, clientIP net.IP, helo, mailFrom, fromDomain string, messageReader io.Reader) (*VerificationResult, error) {
	result := &VerificationResult{}

	// SPF check
	spfResult, spfDetails, err := v.VerifySPF(ctx, clientIP, helo, mailFrom)
	if err != nil {
		v.logger.Warn("SPF verification failed", "error", err)
	}
	result.SPF = spfResult
	result.SPFDomain = extractDomain(mailFrom)
	result.SPFDetails = spfDetails

	// DKIM check
	dkimResult, dkimDetails, dkimDomains, err := v.VerifyDKIM(ctx, messageReader)
	if err != nil {
		v.logger.Warn("DKIM verification failed", "error", err)
	}
	result.DKIM = dkimResult
	if len(dkimDomains) > 0 {
		result.DKIMDomain = dkimDomains[0]
	}
	result.DKIMDetails = dkimDetails

	// DMARC check
	dmarcResult, dmarcPolicy, dmarcDetails, err := v.VerifyDMARC(ctx, fromDomain, spfResult, result.SPFDomain, dkimResult, dkimDomains)
	if err != nil {
		v.logger.Warn("DMARC verification failed", "error", err)
	}
	result.DMARC = dmarcResult
	result.DMARCDomain = fromDomain
	result.DMARCPolicy = dmarcPolicy
	result.DMARCDetails = dmarcDetails

	return result, nil
}

// AuthenticationResultsHeader generates an Authentication-Results header.
func (v *Verifier) AuthenticationResultsHeader(hostname string, result *VerificationResult) string {
	var parts []string

	parts = append(parts, hostname)

	if result.SPF != "" {
		parts = append(parts, fmt.Sprintf("spf=%s smtp.mailfrom=%s", result.SPF, result.SPFDomain))
	}

	if result.DKIM != "" {
		if result.DKIMDomain != "" {
			parts = append(parts, fmt.Sprintf("dkim=%s header.d=%s", result.DKIM, result.DKIMDomain))
		} else {
			parts = append(parts, fmt.Sprintf("dkim=%s", result.DKIM))
		}
	}

	if result.DMARC != "" {
		parts = append(parts, fmt.Sprintf("dmarc=%s header.from=%s", result.DMARC, result.DMARCDomain))
	}

	return strings.Join(parts, "; ")
}

// mapSPFResult converts spf.Result to our SPFResult type.
func mapSPFResult(result spf.Result) SPFResult {
	switch result {
	case spf.None:
		return SPFNone
	case spf.Neutral:
		return SPFNeutral
	case spf.Pass:
		return SPFPass
	case spf.Fail:
		return SPFFail
	case spf.SoftFail:
		return SPFSoftFail
	case spf.TempError:
		return SPFTempError
	case spf.PermError:
		return SPFPermError
	default:
		return SPFNone
	}
}

// mapDMARCPolicy converts dmarc.Policy to our DMARCPolicy type.
func mapDMARCPolicy(policy dmarc.Policy) DMARCPolicy {
	switch policy {
	case dmarc.PolicyQuarantine:
		return DMARCPolicyQuarantine
	case dmarc.PolicyReject:
		return DMARCPolicyReject
	default:
		return DMARCPolicyNone
	}
}

// checkAlignment checks if two domains are aligned according to DMARC rules.
func checkAlignment(fromDomain, authDomain string, mode dmarc.AlignmentMode) bool {
	fromDomain = strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))

	if mode == dmarc.AlignmentStrict {
		return fromDomain == authDomain
	}

	// Relaxed mode - organizational domain match
	return getOrgDomain(fromDomain) == getOrgDomain(authDomain)
}

// getOrgDomain extracts the organizational domain (simplified).
// In production, this should use the public suffix list.
func getOrgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// extractDomain extracts the domain from an email address.
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return email
}
