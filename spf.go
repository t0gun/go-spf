package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Result defines the outcome of an SPF check.
// https://tools.ietf.org/html/rfc7208#section-8
type Result string

const (
	// None result means the check host completed without errors and not able to reach any conclusion.
	// https://tools.ietf.org/html/rfc7208#section-8.1
	None = Result("none")

	// Neutral indicates there is an SPF policy but no definitive assertation (positive or negative)
	// https://tools.ietf.org/html/rfc7208#section-8.2
	Neutral = Result("neutral")

	// Pass indicates the client is authorized to inject mail
	// https://tools.ietf.org/html/rfc7208#section-8.3
	Pass = Result("pass")

	// Fail indicates the client is not authorized to use the domain
	// https://tools.ietf.org/html/rfc7208#section-8.4
	Fail = Result("fail")

	// SoftFail indicates the client is not authorized but willing to make a strong policy statement
	// https://tools.ietf.org/html/rfc7208#section-8.5
	SoftFail = Result("softfail")

	// TempError indicates a DNS error occurred while performing the check
	// https://tools.ietf.org/html/rfc7208#section-8.6
	TempError = Result("temperror")

	// PermError indicates the domain published records could not be interpreted
	// https://tools.ietf.org/html/rfc7208#section-8.7
	PermError = Result("permerror")
)

var (
	// Errors related to DNS lookups

	// ErrMultipleRecords indicates that multiple DNS records of the same type were
	// found when only one was expected.
	ErrMultipleRecords = errors.New("duplicate DNS records")

	ErrNoRecordFound = errors.New("the specified record cant be found")

	ErrLookupLimitReached = errors.New("lookup limit reached")
)

const (
	// MaxDNSLookups defines the maximum number of DNS-query-causing mechanism/modifiers.Exceeding this limit
	// results in a PermError
	// Reference: RFC 7208 Section 4.6.4
	// https://tools.ietf.org/html/rfc7208#section-4.6.4
	MaxDNSLookups = 10

	// MaxVoidLookups defines the maximum number of "void": DNS lookups.
	// lookups that return no usable records allowed during SPF evaluation
	// Exceeding this limit result in a PermError
	// Reference: RFC 7208 Section 4.6.4
	// https://tools.ietf.org/html/rfc7208#section-4.6.4
	MaxVoidLookups = 2
)

var (
// Errors related to SPF lookup
)

func ParseSPF(txt string) ([]string, error) {
	if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
		return nil, fmt.Errorf("invalid SPF record")
	}

	return strings.Fields(txt)[1:], nil
}

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
