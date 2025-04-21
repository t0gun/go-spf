package spf

import (
	"context"
	"errors"
	"net"
	"strings"
)

var (
	ErrMultipleSPF = errors.New("filter found multiple spf records (permerror)")
)

// TXTResolver defines DNS-TXT lookup behaviour
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) (string, error)
}

// DNSResolver wraps Go's *net.Resolver.
type DNSResolver struct {
	resolver *net.Resolver
}

func (d *DNSResolver) LookupTXT(ctx context.Context, domain string) (string, error) {
	txts, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", err
	}

	spf, err := filterSPF(txts)
	if spf == "" && errors.Is(err, ErrMultipleSPF) {
		return "", ErrMultipleSPF // Return to parent to call perm error
	}

	return spf, nil
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: net.DefaultResolver,
	}
}

// filterSPF returns only a single SPF record from a list of TXTs  (RFC 7208 § 3.1).
func filterSPF(txts []string) (string, error) {
	var records []string

	for _, txt := range txts {
		spf := strings.TrimSpace(txt) // some records can have a leading and trailing white space

		// records begin with a version "v=spf1" (RFC § 4.5).
		if strings.HasPrefix(strings.ToLower(spf), "v=spf1 ") {
			records = append(records, spf)
		}

		// some records can end with the version. (RFC 7208 § 4.5).
		if strings.ToLower(spf) == "v=spf1" {
			records = append(records, spf)
		}

	}
	// § 4.5: 0 → none; 1 → ok; >1 → permerror
	switch len(records) {
	case 0:
		return "", nil // allowed

	case 1:
		return records[0], nil

	default:
		return "", ErrMultipleSPF

	}

}
