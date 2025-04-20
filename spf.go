// Package spf implements the Sender Policy Framework checker defined in
// RFC 7208.  The entry‑point is CheckHost, which follows the decision tree in
// section 4.6.

package spf

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Result is the outcome of an SPF evaluation (RFC 7208 §8).
type Result string

const (
	None      Result = "none"      // no SPF record
	Neutral   Result = "neutral"   // policy exists but gives no assertion
	Pass      Result = "pass"      // client is authorized
	Fail      Result = "fail"      // client is NOT authorized
	SoftFail  Result = "softfail"  // not authorized, but weak assertion
	TempError Result = "temperror" // transient DNS error
	PermError Result = "permerror" // perm error in record or >10 look‑ups
)

// Limits from RFC 7208 §4.6.4.
const (
	MaxDNSLookups  = 10 // any mechanism that triggers DNS counts
	MaxVoidLookups = 2  // DNS look‑ups returning no usable data
)

type Checker struct {
	Resolver       TXTResolver
	MaxLookups     int
	MaxVoidLookups int
	// Extensible
}

func NewChecker(r TXTResolver) *Checker {
	return &Checker{
		Resolver:       r,
		MaxLookups:     MaxDNSLookups,
		MaxVoidLookups: MaxVoidLookups,
	}

}

// CheckHost implements RFC 7208 §4.6 (the “check_host” function)
// domain – Domain whose SPF record we start with. Usually:
//   - the HELO/EHLO hostname, if you’re doing an initial HELO check;
//   - otherwise the domain part of MAIL FROM.
//
// sender – The full MAIL FROM address (<> for bounces). Used only for
//
//	macro expansion; leave empty if you’re just checking HELO.
func (c *Checker) CheckHost(ctx context.Context, ip net.IP, domain, sender string) (Result, error) {

	// if we reached the end without any match, RFC says neutral
	return Neutral, nil
}

// Convenience wrapper for minimal api
var defaultChecker = NewChecker(NewDNSResolver())

// CheckHost - function here is a package level checker. it's wrapped around the original API
// Mostly for callers, not interested in customization.
func CheckHost(ip net.IP, domain, sender string) (Result, error) {
	return defaultChecker.CheckHost(context.Background(), ip, domain, sender)
}

///////////////////////////////////////////////////// HELPERS  ///////////////////////////////////////////////////////

// filterSPF returns only the TXT entries that are valid SPF1 records (RFC 7208 § 3.1).
func filterSPF(txts []string) []string {
	var SPFs []string
	for _, txt := range txts {
		spf := strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(spf), "v=spf1") {
			SPFs = append(SPFs, spf)
		}
	}
	return SPFs
}

// parseSPF : basic parser
func parseSPF(txt string) ([]string, error) {
	if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
		return nil, fmt.Errorf("invalid SPF record")
	}
	return strings.Fields(txt)[1:], nil
}

// getSenderDomain extracts the domain part of a MAIL FROM address per RFC 7208 § 4.1.
// It returns the portion after the first '@', and ok==true if an '@' was present.
// If sender contains no '@', it returns ("", false).
func getSenderDomain(sender string) (string, bool) {
	parts := strings.SplitN(sender, "@", 2)
	if len(parts) == 2 {
		return parts[1], true
	}
	return "", false
}
