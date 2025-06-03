// Package spf implements the Sender Policy Framework checker defined in
// RFC 7208.  The entry‑point is CheckHost, which follows the decision tree in
// section 4.6.

package spf

import (
	"context"
	"errors"
	"golang.org/x/net/idna"
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

// Errors returned by validateDomain RFC Section 4.3
var (
	ErrSingleLabel    = errors.New("domain must have at least two labels")
	ErrEmptyLabel     = errors.New("domain has empty label")
	ErrLabelTooLong   = errors.New("domain label exceeds 63 octets")
	ErrDomainTooLong  = errors.New("domain exceeds 255 octets")
	ErrIDNAConversion = errors.New("IDNA ToASCII failed")
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
	// Extensible
}

// NewChecker returns a Checker that uses the given TXTResolver.
func NewChecker(r TXTResolver) *Checker {
	return &Checker{
		Resolver:       r,
		MaxLookups:     MaxDNSLookups,
		MaxVoidLookups: MaxVoidLookups,
	}

}

type CheckHostResult struct {
	Code  Result
	Cause error
}

// Convenience wrapper for minimal api.
var defaultChecker = NewChecker(NewDNSResolver())

// CheckHost implements RFC 7208 section 4.6 (the “check_host” function)
// domain – Domain whose SPF record we start with. Usually:
//   - the HELO/EHLO hostname, if you’re doing an initial HELO check;
//   - otherwise the domain part of MAIL FROM.
//
// Sender – The full MAIL FROM address (<> for bounces). Used only for
//
// Macro expansion; leave empty if you’re just checking HELO.
func (c *Checker) CheckHost(ctx context.Context, ip net.IP, domain, sender string) (CheckHostResult, error) {
	valDomain, err := ValidateDomain(domain)
	if err != nil {
		// RFC 7208 section 4.3 malformed domain results to none
		return CheckHostResult{Code: None, Cause: err}, nil
	}
	domain = valDomain

	spfRecord, err := getSPFRecord(ctx, domain, c.Resolver)

	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
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


	// if we reached the end without any match, RFC says neutral
	return CheckHostResult{Code: Neutral, Cause: errors.New("policy exist but no given assertation")}, nil
}

// CheckHost - function here is a package level checker. it's wrapped around the original API
// Mostly for callers, not interested in customization.
func CheckHost(ip net.IP, domain, sender string) (CheckHostResult, error) {
	return defaultChecker.CheckHost(context.Background(), ip, domain, sender)
}

// getSenderDomain extracts the domain part of a MAIL FROM address per RFC 7208 section 4.1.
// It returns the portion after the first '@', and ok==true if an '@' was present.
// If sender contains no '@', it returns ("", false).
func getSenderDomain(sender string) (string, bool) {
	numofParts := 2
	parts := strings.SplitN(sender, "@", numofParts)
	if len(parts) == numofParts {
		return parts[1], true
	}

	return "", false
}

// ValidateDomain normalises and validates a raw domain name, according to
// RFC 7208, section 4.3.
//
// Validation steps:
//
//  1. Remove one trailing dot because domains are implicitly absolute.
//
//  2. Convert the name to its Punycode A-label form with idna.Lookup.ToASCII.
//
//  3. Apply SPF pre-evaluation checks:
//
//     * Overall length must not exceed 255 octets.
//     * The domain must contain at least two labels (must include a dot).
//     * No empty label may appear except the implicit root.
//     * Each label must be 1–63 octets long.
//     * Labels may contain only lower-case letters, digits, and hyphens.
//     * A hyphen may not appear at the start or end of any label.
//
// On success the function returns the ASCII (lower-case) domain and nil.
// On failure, it returns an empty string and one of the sentinel errors
// and similar.
func ValidateDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	// Trim the single trailing dot if any
	raw = strings.TrimSuffix(raw, ".")

	// convert to A-label RFC 5890 section 2.3
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", ErrIDNAConversion
	}
	ascii = strings.ToLower(ascii)

	// check overall length limit
	if len(ascii) > 255 {
		return "", ErrDomainTooLong
	}

	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrSingleLabel
	}

	for _, lbl := range labels {
		switch {
		case len(lbl) == 0:
			return "", ErrEmptyLabel

		case len(lbl) > 63:
			return "", ErrLabelTooLong

		}

	}

	return ascii, nil
}
