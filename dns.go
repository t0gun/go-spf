package spf

import (
	"context"
	"net"
)

// TXTResolver defines DNS-TXT lookup behaviour
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// DNSResolver wraps Go's *net.Resolver.
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
