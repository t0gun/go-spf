package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Errors related to DNS Lookups
var (
	ErrMultipleSPF = errors.New("filter found multiple spf records (permerror)")
	ErrNoDNSrecord = errors.New("DNS record not found")
	ErrTempErr     = errors.New("temperror: temporary DNS lookup failure")
	ErrPermErr     = errors.New("permerror: permanent DNS lookup failure")
)

// TXTResolver fetches all TXT records for a domain.
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// DNSResolver uses Go's stdlib to implement TXTResolver.
type DNSResolver struct {
	resolver *net.Resolver
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: net.DefaultResolver,
	}
}

func (d *DNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return d.resolver.LookupTXT(ctx, domain)
}

// GetSPFRecord performs an RFC‑compliant SPF lookup.
//   - NXDOMAIN → ("", ErrNoDNSrecord)
//   - SERVFAIL/timeout → ErrTempErr
//   - any other error → ErrPermErr
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
				return "", fmt.Errorf("%w: %v", ErrTempErr, err)
			}
		}
		return "", fmt.Errorf("%w: %v", ErrPermErr, err)
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
		return found[0], nil

	default:
		return "", ErrMultipleSPF

	}

}
