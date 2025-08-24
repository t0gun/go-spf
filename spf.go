// Package spf implements a checker for the Sender Policy Framework as defined
// by RFC 7208.  The primary entry point is CheckHost which walks the decision
// tree in section 4.6 to determine the authorization result for a given IP
// and domain.

package spf

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/t0gun/go-spf/dns"
	"github.com/t0gun/go-spf/parser"
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
	Resolver       *dns.Resolver
	MaxLookups     int
	MaxVoidLookups int
	Lookups        int
	Voids          int
	// Future fields may allow customization of evaluation behaviour.
}

// NewChecker returns a Checker that uses the given TXTResolver.
func NewChecker(r *dns.Resolver) *Checker {
	return &Checker{
		Resolver:       r,
		MaxLookups:     MaxDNSLookups,
		MaxVoidLookups: MaxVoidLookups,
		Lookups:        0,
		Voids:          0,
	}

}

// CheckHostResult contains the result code and optional cause returned by
type CheckHostResult struct {
	Code  Result
	Cause error
}

// defaultChecker backs the package-level CheckHost convenience function.
var defaultChecker = NewChecker(dns.NewDNSResolver())

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
	spfRecord, err := dns.GetSPFRecord(ctx, domain, c.Resolver)

	// Apply the record-selection logic from RFC 7208 section 4.5.
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Context errors are outside the scope of RFC 7208.
		return CheckHostResult{}, err
	case errors.Is(err, dns.ErrNoDNSrecord):
		return CheckHostResult{Code: None, Cause: err}, err
	case errors.Is(err, dns.ErrTempfail):
		return CheckHostResult{Code: TempError, Cause: err}, nil
	case errors.Is(err, dns.ErrPermfail), errors.Is(err, dns.ErrMultipleSPF):
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

// evaluate walks the mechanisms in the order they appear in the record.
// RFC 7208 §4.6 requires sequential evaluation; the first mechanism that
// matches terminates processing.
func (c *Checker) evaluate(ctx context.Context, ip net.IP, domain, spf, localPart string) (CheckHostResult, error) {
	rec, err := parser.Parse(spf)
	if err != nil {
		return CheckHostResult{Code: PermError, Cause: err}, nil
	}
	// Walk mechanisms in order as required by RFC 7208 section 4.6.  Only
	for _, mech := range rec.Mechs {
		switch mech.Kind {
		case "ip4":
			if ip4 := ip.To4(); ip4 != nil && mech.Net.Contains(ip4) {
				return CheckHostResult{Code: resultFromQualifier(mech.Qual)}, nil
			}
		case "ip6":
			// Only match pure IPv6. IPv4-mapped addresses fall into ip4 via To4().
			if ip.To4() == nil {
				if ip6 := ip.To16(); ip6 != nil && mech.Net.Contains(ip6) {
					return CheckHostResult{Code: resultFromQualifier(mech.Qual)}, nil
				}
			}
		case "a":
			// RFC  7208 section 5.3 - "a" mechanisms compare the sender IP against the A/AAAA records of the current pr
			// explicit domain
			ok, derr := c.evalA(ctx, mech, ip, domain)
			if derr != nil {
				// RFC  7208 section 2.6.4/2.6.5 DNS errors map to Temp/PermError
				if errors.Is(derr, context.Canceled) || errors.Is(derr, context.DeadlineExceeded) {
					return CheckHostResult{}, derr
				}
				if errors.Is(derr, dns.ErrTempfail) {
					return CheckHostResult{Code: TempError, Cause: derr}, nil
				}
				return CheckHostResult{Code: PermError, Cause: derr}, nil
			}
			if ok {
				// RFC section 4.6, first match wins, qualifier determines result.
				return CheckHostResult{Code: resultFromQualifier(mech.Qual)}, nil
			}
			// No match continue with next mechanism

		case "all":
			// RFC 7208 5.1 - all always matches and everything after must be ignored.
			return CheckHostResult{Code: resultFromQualifier(mech.Qual)}, nil
		}
	}
	// RFC 7208 4.7 - default if no mechanism matched and no redirect is Neutral.
	return CheckHostResult{Code: Neutral, Cause: errors.New("policy exists but no assertion")}, nil
}

// evalA evaluates the "a" mechanism - RFC 7208 section 5.3
// Semantics:
// target domain is either the current SPF domain or the one specified after the a:prefix
// the sender ip matches it if it falls within any A ipv4 or AAAA ipv6 record for the targe domain after applying CIDR masks
// each DNS lookup increments the SPF DNS-lookup counter. rfc 7208 section 4.6.4
// empty DNS responses count towards the "void lookup" limit .RFC 7208 section 4.6.4
// Errors are mapped to TemprError and PermError as per RFC 7208 section 2.6.4 and 2.6.5
func (c *Checker) evalA(ctx context.Context, mech parser.Mechanism, connectIP net.IP, currentDomain string) (matched bool, err error) {
	// section 5.3 - default to the current domain if none is provided
	target := mech.Domain
	if target == "" {
		target = currentDomain
	}
	// section 4.6.6 Enforce the global DNS-lookup limit
	c.Lookups++
	if c.Lookups > c.MaxLookups {
		return false, dns.ErrPermfail
	}

	// perform A/AAAA lookup
	ips, err := c.Resolver.LookupIP(ctx, target)
	if err != nil {
		// section 2.6 , context cancellation is not SPF specific, we propagate
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		// section 2.6.4 , temporary DNS error => TempError
		var dErr *net.DNSError
		if errors.As(err, &dErr) && dErr.Temporary() {
			return false, dns.ErrTempfail
		}

		// section 2.6.5, other DNS errors => PermError
		return false, dns.ErrPermfail
	}

	// section 4.6.4 - void lookups: domain exists but no usable A/AAAA
	if len(ips) == 0 {
		c.Voids++
		if c.Voids > c.MaxVoidLookups {
			return false, dns.ErrPermfail
		}
		return false, nil
	}

	// section 5.6IPv4 mask = /32, IPv6 mask = 128 if omitted
	mask4 := mech.Mask4
	if mask4 < 0 {
		mask4 = 32
	}

	mask6 := mech.Mask6
	if mask6 < 0 {
		mask6 = 128
	}

	// compare sender IP against  each returned address
	if connectIP.To4() != nil {
		cip := connectIP.To4()
		for _, tip := range ips {
			if t4 := tip.To4(); t4 != nil && prefixEqual(cip, t4, mask4, 32) {
				return true, nil // section 4.6 rfc 7208, first match wins
			}
		}
		return false, nil
	}

	// Sender is IPv6
	cip6 := connectIP.To16()
	if cip6 == nil {
		return false, nil
	}
	for _, tip := range ips {
		if tip.To4() == nil && prefixEqual(cip6, tip.To16(), mask6, 128) {
			return true, nil
		}
	}

	return false, nil
}

// prefixEqual compares two IPs under a given prefix length.
// Used to implement CIDR matching for "a" and "mx" mechanisms.
//
// Returns true if the first maskLen bits are identical.
//   - totalBits = 32 for IPv4, 128 for IPv6.
//   - 5.6 requires bounds-checking on CIDR lengths.
func prefixEqual(a, b net.IP, maskLen, totalBits int) bool {
	if a == nil || b == nil || maskLen < 0 || maskLen > totalBits {
		return false
	}
	aa := a.To16()
	bb := b.To16()
	if aa == nil || bb == nil {
		return false
	}
	mask := net.CIDRMask(maskLen, totalBits)
	for i := 0; i < len(mask); i++ {
		if (aa[i] & mask[i]) != (bb[i] & mask[i]) {
			return false
		}
	}
	return true
}

func resultFromQualifier(q parser.Qualifier) Result {
	switch q {
	case parser.QPlus:
		return Pass
	case parser.QMinus:
		return Fail
	case parser.QTilde:
		return SoftFail
	case parser.QMark:
		return Neutral
	default:
		return Neutral
	}
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
