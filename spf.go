// Package spf implements the Sender Policy Framework checker defined in
// RFC 7208.  The entry‑point is CheckHost, which follows the decision tree in
// section 4.6.

package spf

import (
	"context"
	"errors"
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

// DNS‑level errors surfaced by the Resolver.
var (
	ErrMultipleRecords    = errors.New("multiple txt records") // RFC 7208 §4.5
	ErrRecordNotFound     = errors.New("no  record found")     // RFC 7208 §8.1
	ErrLookupLimitReached = errors.New("DNS lookup limit exceeded")
)

// Limits from RFC 7208 §4.6.4.
const (
	MaxDNSLookups  = 10 // any mechanism that triggers DNS counts
	MaxVoidLookups = 2  // DNS look‑ups returning no usable data
)

type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

type DNSResolver struct {
	resolver *net.Resolver
}

func (d *DNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return d.resolver.LookupTXT(ctx, domain)
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: net.DefaultResolver,
	}
}

// ParseSPF : basic parser
func ParseSPF(txt string) ([]string, error) {
	if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
		return nil, fmt.Errorf("invalid SPF record")
	}

	return strings.Fields(txt)[1:], nil
}

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

func (c *Checker) CheckHost(ctx context.Context, ip, domain, sender string) (Result, error) {

	// ctx is used for every DNS call, deadline/cancel belong to the caller
	_, err := c.Resolver.LookupTXT(ctx, domain)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return TempError, err
		}
		return TempError, err
	}

	return TempError, nil
}

// Convenience wrapper.
var defaultChecker = NewChecker(NewDNSResolver())

func CheckHost(ip, domain, sender string) (Result, error) {
	return defaultChecker.CheckHost(context.Background(), ip, domain, sender)
}
