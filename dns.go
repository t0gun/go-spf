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

// Errors returned during DNS lookups.  They map directly to the
// conditions described in RFC 7208 section 4.5 when locating and
// selecting an SPF record.
var (
	ErrMultipleSPF = errors.New("filter found multiple spf records (permerror)")
	ErrNoDNSrecord = errors.New("DNS record not found (NXDOMAIN)")
	ErrTempfail    = errors.New("temperror: temporary DNS lookup failure")
	ErrPermfail    = errors.New("permerror: permanent DNS lookup failure")
)

// DefaultDialTimeout is the fallback time out if the caller does not pass a deadline/cancellation.
const DefaultDialTimeout = 5 * time.Second

// TXTResolver abstracts DNS lookups for TXT records.  Implementations
// should return all TXT strings for the supplied domain as required by
// RFC 7208 section 3.3.
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// DNSResolver uses Go's stdlib to implement TXTResolver.
type DNSResolver struct {
	resolver TXTResolver
}

// NewDNSResolver returns a DNSResolver that performs TXT lookups using the
// Go standard library.  Lookups respect context timeouts and cancellations so
// callers can enforce the limits from RFC 7208 section 11.
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

// NewCustomDNSResolver builds a DNSResolver that delegates TXT lookups to the
// provided implementation.  Use this for unit tests or when DNS queries need to
// be customised.
func NewCustomDNSResolver(r TXTResolver) *DNSResolver {
	return &DNSResolver{resolver: r}
}

// LookupTXT forwards the request to the underlying resolver.  The provided
// context controls timeouts so callers remain compliant with the DNS
// considerations in RFC 7208 section 11.
func (d *DNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return d.resolver.LookupTXT(ctx, domain)
}

// getSPFRecord retrieves the TXT records for domain and selects the single
// valid SPF record.  The behaviour mirrors the DNS processing rules from
// RFC 7208 section 4.5.
//   - NXDOMAIN → ("", ErrNoDNSrecord)
//   - SERVFAIL/timeout → ErrTempfail
//   - any other error → ErrPermfail
//   - then filters for exactly one "v=spf1" record.
func getSPFRecord(ctx context.Context, domain string, r TXTResolver) (string, error) {
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err // propagate – let the caller decide
		}

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

// filterSPF selects exactly one "v=spf1" string from the provided TXT records.
// The selection logic implements RFC 7208 section 4.5:
//   - 0 records → ("", nil)
//   - 1 record → (that record, nil)
//   - more than 1 → ("", ErrMultipleSPF)
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

	// section 4.5: 0 → none; 1 → ok; >1 → permerror
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
