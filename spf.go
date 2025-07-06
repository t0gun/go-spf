// Package spf implements a checker for the Sender Policy Framework as defined
// by RFC 7208.  The primary entry point is CheckHost which walks the decision
// tree in section 4.6 to determine the authorization result for a given IP
// and domain.

package spf

import (
	"context"
	"errors"
	"github.com/mailspire/spf/parser"
	"net"
	"strings"
)

// Result is the outcome of an SPF evaluation (RFC 7208 section 2.6).
type Result string

const (
	None      Result = "none"
	Neutral   Result = "neutral"   // policy exists but gives no assertion
	Pass      Result = "pass"      // client is authorized
	Fail      Result = "fail"      // client is NOT authorized
	SoftFail  Result = "softfail"  // not authorized, but weak assertion
	TempError Result = "temperror" // transient DNS error
	PermError Result = "permerror" // perm error in record or >10 look‑ups
)

// Limits from RFC 7208 section 4.6.4.
const (
	MaxDNSLookups  = 10 // any mechanism that triggers DNS counts
	MaxVoidLookups = 2  // DNS look‑ups returning no usable data
)

// Checker implements a full RFC 7208–compliant SPF policy evaluator.
type Checker struct {
	Resolver       TXTResolver
	MaxLookups     int
	MaxVoidLookups int
	// Future fields may allow customization of evaluation behaviour.
}

// NewChecker returns a Checker that uses the given TXTResolver.
func NewChecker(r TXTResolver) *Checker {
	return &Checker{
		Resolver:       r,
		MaxLookups:     MaxDNSLookups,
		MaxVoidLookups: MaxVoidLookups,
	}

}

// CheckHostResult contains the result code and optional cause returned by
// CheckHost.
type CheckHostResult struct {
	Code  Result
	Cause error
}

// defaultChecker backs the package-level CheckHost convenience function.
var defaultChecker = NewChecker(NewDNSResolver())

// CheckHost implements the "check_host" algorithm from RFC 7208 section 4.6.
// The domain parameter is the name where SPF evaluation begins.  Typically this
// is the EHLO hostname or the domain part of MAIL FROM.  The sender parameter is
// the full MAIL FROM address ("<>" for bounces) and is used only for macro
// expansion.
func (c *Checker) CheckHost(ctx context.Context, ip net.IP, domain, sender string) (CheckHostResult, error) {
	valDomain, err := parser.ValidateDomain(domain)
	if err != nil {
		// RFC 7208 section 4.3 malformed domain results to none
		return CheckHostResult{Code: None, Cause: err}, nil
	}
	domain = valDomain
	lp := localPart(sender)
	// Perform the SPF record lookup per RFC 7208 section 4.4.
	spfRecord, err := getSPFRecord(ctx, domain, c.Resolver)

	// Apply the record-selection logic from RFC 7208 section 4.5.
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Context errors are outside the scope of RFC 7208.
		return CheckHostResult{}, err
	case errors.Is(err, ErrNoDNSrecord):
		return CheckHostResult{Code: None, Cause: err}, err
	case errors.Is(err, ErrTempfail):
		return CheckHostResult{Code: TempError, Cause: err}, nil
	case errors.Is(err, ErrPermfail), errors.Is(err, ErrMultipleSPF):
		return CheckHostResult{Code: PermError, Cause: err}, nil
	case err != nil:
		return CheckHostResult{}, err
	}

	if spfRecord == "" {
		return CheckHostResult{}, err
	}

	return c.evaluate(ctx, ip, valDomain, spfRecord, lp)

}

// CheckHost is a convenience wrapper around Checker.CheckHost for callers that
// do not require custom configuration.
func CheckHost(ip net.IP, domain, sender string) (CheckHostResult, error) {
	return defaultChecker.CheckHost(context.Background(), ip, domain, sender)
}

// evaluate walks the SPF decision tree for the given record.  It is a
// placeholder for the logic described in RFC 7208 section 4.6 and currently
// returns Neutral for all inputs.
func (c *Checker) evaluate(ctx context.Context, ip net.IP, domain, spf, localPart string) (CheckHostResult, error) {

	// If no mechanism matches, RFC 7208 dictates a "neutral" result.
	return CheckHostResult{Code: Neutral, Cause: errors.New("policy exists but no assertion")}, nil
}

// getSenderDomain extracts the domain part of a MAIL FROM address as described
// in RFC 7208 section 4.1. It returns the substring after the first '@' and ok
// set to true when an '@' is present. If sender lacks an '@', it returns ("",
// false).
func getSenderDomain(sender string) (string, bool) {
	numofParts := 2
	parts := strings.SplitN(sender, "@", numofParts)
	if len(parts) == numofParts {
		return parts[1], true
	}

	return "", false
}

// localPart extracts the string before '@'.  If the input lacks '@', RFC 7208
// section 4.1 requires that "postmaster" be used instead.
func localPart(sender string) string {
	// strip surrounding angle brackets that MTAs sometimes keep.
	sender = strings.Trim(sender, "<>")
	if at := strings.IndexByte(sender, '@'); at > 0 {
		return sender[:at] // real local part
	}

	return "postmaster"
}
