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
	"time"
)

// Errors related to DNS Lookups.
var (
	ErrMultipleSPF = errors.New("filter found multiple spf records (permerror)")
	ErrNoDNSrecord = errors.New("DNS record not found")
	ErrTempfail    = errors.New("temperror: temporary DNS lookup failure")
	ErrPermfail    = errors.New("permerror: permanent DNS lookup failure")
)

// DefaultDialTimeout is the fallback time out if the caller does not pass a deadline/cancellation.
const DefaultDialTimeout = 5 * time.Second

// TXTResolver fetches all TXT records for a domain.
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// DNSResolver uses Go's stdlib to implement TXTResolver.
type DNSResolver struct {
	resolver TXTResolver
}

// NewDNSResolver returns a DNSResolver whose lookups will honor ctx deadlines/cancellations.
func NewDNSResolver() *DNSResolver {
	r := &net.Resolver{
		StrictErrors: true,
		PreferGo:     true, // force pure-Go DNS implementation
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{ //nolint:exhaustruct
				Timeout: DefaultDialTimeout,
			}

			return d.DialContext(ctx, network, address)
		},
	}

	return &DNSResolver{resolver: r}
}

// NewCustomDNSResolver allow callers to apply their own custom resolver.
func NewCustomDNSResolver(r TXTResolver) *DNSResolver {
	return &DNSResolver{resolver: r}
}

func (d *DNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return d.resolver.LookupTXT(ctx, domain)
}

// GetSPFRecord performs an RFC‑compliant SPF lookup.
//   - NXDOMAIN → ("", ErrNoDNSrecord)
//   - SERVFAIL/timeout → ErrTempfail
//   - any other error → ErrPermfail
//   - then filters for exactly one "v=spf1" record.
func (d *DNSResolver) GetSPFRecord(ctx context.Context, domain string) (string, error) {
	txts, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsNotFound:
				return "", ErrNoDNSrecord
			case dnsErr.Temporary():
				return "", fmt.Errorf("%w: %w", ErrTempfail, err)
			}
		}

		return "", fmt.Errorf("%w: %w", ErrPermfail, err)
	}

	return filterSPF(txts)
}

// filterSPF picks exactly one "v=spf1" record (RFC 7208 §4.5).
//   - 0 records → ("", nil)
//   - 1 record → (that record, nil)
//   - >1 record → ("", ErrMultipleSPF)
func filterSPF(txts []string) (string, error) {
	const spfV1 = "v=spf1"
	var found []string

	for _, raw := range txts {
		s := strings.TrimSpace(raw)
		fields := strings.Fields(s)
		if len(fields) > 0 && strings.EqualFold(fields[0], spfV1) {
			found = append(found, s)
		}
	}

	// § 4.5: 0 → none; 1 → ok; >1 → permerror
	switch len(found) {
	case 0:
		return "", nil // allowed

	case 1:
		foundSpf := strings.ToLower(found[0])
		return foundSpf, nil

	default:
		return "", ErrMultipleSPF
	}
}
