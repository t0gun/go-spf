package parser

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- quick helpers ---------- //
func mech(q Qualifier, kind string) Mechanism {
	return Mechanism{Qual: q, Kind: kind}
}

func mechip4(q Qualifier, cidr string) Mechanism {
	_, n, _ := net.ParseCIDR(cidr)
	return Mechanism{Qual: q, Kind: "ip4", Net: n}
}

func mechip6(q Qualifier, cidr string) Mechanism {
	_, n, _ := net.ParseCIDR(cidr)
	return Mechanism{Qual: q, Kind: "ip6", Net: n}
}

func aMech(q Qualifier, domain string, m4, m6 int) Mechanism {
	return Mechanism{Qual: q, Kind: "a", Domain: domain, Mask4: m4, Mask6: m6}
}

func mxMech(q Qualifier, domain string, m4, m6 int) Mechanism {
	return Mechanism{Qual: q, Kind: "mx", Domain: domain, Mask4: m4, Mask6: m6}
}

func ptrMech(q Qualifier, domain string, hasMacro bool) Mechanism {
	return Mechanism{Qual: q, Kind: "ptr", Domain: domain, Macro: hasMacro}
}

func existMech(q Qualifier, domain string, hasMacro bool) Mechanism {
	return Mechanism{Qual: q, Domain: domain, Macro: hasMacro}
}

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		spf     string
		want    []Mechanism
		wantErr bool
	}{
		// Ipv4 mechanism tests
		{
			name: "ip4 then -all",
			spf:  "v=spf1 ip4:203.0.113.0/24 -all",
			want: []Mechanism{mechip4(QPlus, "203.0.113.0/24"), mech(QMinus, "all")},
		},

		{
			name: "implicit +all",
			spf:  "v=spf1 all",
			want: []Mechanism{mech(QPlus, "all")}},

		{
			name:    "bad cidr ip4",
			spf:     "v=spf1 ip4:203.0.113.0/99 -all",
			wantErr: true,
		},
		{
			name: "ip4 with no mask then ~all",
			spf:  "v=spf1 +ip4:203.0.113.23 ~all",
			want: []Mechanism{mechip4(QPlus, "203.0.113.23/32"), mech(QTilde, "all")},
		},

		{
			name: "ip6 and ip4 then -all",
			spf:  "v=spf1 ip6:2001:db8::/32 ip4:203.0.113.0/24 -all",
			want: []Mechanism{mechip6(QPlus, "2001:db8::/32"), mechip4(QPlus, "203.0.113.0/24"), mech(QMinus, "all")},
		},

		{
			name: "implicit /128 host",
			spf:  "v=spf1 ip6:2001:db8::1 -all",
			want: []Mechanism{mechip6(QPlus, "2001:db8::1/128"), mech(QMinus, "all")},
		},
		{
			name:    "bad ipv6 cidr",
			spf:     "v=spf1 ip6:2001:db8::/200 -all",
			wantErr: true,
		},

		{
			name: "bare a defaults with all",
			spf:  "v=spf1 a -all",
			want: []Mechanism{aMech(QPlus, "", -1, -1), mech(QMinus, "all")},
		},
		{
			name: "a with /24",
			spf:  "v=spf1 a/24 -all",
			want: []Mechanism{aMech(QPlus, "", 24, -1), mech(QMinus, "all")},
		},
		{
			name: "a explicit domain dual masks",
			spf:  "v=spf1 a:mail.example.com/24/64 -all",
			want: []Mechanism{aMech(QPlus, "mail.example.com", 24, 64), mech(QMinus, "all")},
		},
		{
			name:    "a bad v4 mask",
			spf:     "v=spf1 a/33 -all",
			wantErr: true,
		},
		{
			name:    "a too many slashes",
			spf:     "v=spf1 a24/64/96 -all",
			wantErr: true,
		},
		{
			name: "mx with masks",
			spf:  "v=spf1 mx/24 -all",
			want: []Mechanism{mxMech(QPlus, "", 24, -1), mech(QMinus, "all")},
		},

		{
			name: "mx explicit domain, dual masks",
			spf:  "v=spf1 mx:mail.example.org/24/64 -all",
			want: []Mechanism{mxMech(QPlus, "mail.example.org", 24, 64), mech(QMinus, "all")},
		},
		{
			name:    "mx bad v6 mask",
			spf:     "v=spf1 mx/124/129 ~all",
			wantErr: true,
		},
		{
			name: "bare ptr then -all",
			spf:  "v=spf1 ptr -all",
			want: []Mechanism{ptrMech(QPlus, "", false), mech(QMinus, "all")},
		},
		{
			name: "ptr explicit domain with softfail all",
			spf:  "v=spf1 ~ptr:example.com -all",
			want: []Mechanism{ptrMech(QTilde, "example.com", false), mech(QMinus, "all")},
		},
		{
			name: "ptr containing macro then -all",
			spf:  "v=spf1 ptr:%{d} -all",
			want: []Mechanism{ptrMech(QPlus, "%{d}", true), mech(QMinus, "all")},
		},
		{
			name:    "ptr bad domain",
			spf:     "v=spf1 ptr:invalid_domain -all",
			wantErr: true,
		},
		{
			name:    "ptr with garbage suffix",
			spf:     "v=spf1 ptrfoo -all",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Parse(tc.spf)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, rec.Mechs, tc.want)
		})
	}

}

func TestValidateDomain(t *testing.T) {
	t.Parallel()
	var longLabel = strings.Repeat("a", 64) + ".com"
	var longName = strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 63),
	}, ".") + ".com" // 4×63 + 3 dots = 255, OK
	var tooLongName = longName + "e" // 256 bytes, rejects
	tc := []struct {
		name    string // name of test
		raw     string
		wantErr bool
		Err     error
		output  string
	}{
		// valid domain names
		{"valid-domain-1", "example.com", false, nil, "example.com"},
		{"valid-domain-2", "example.ORG.", false, nil, "example.org"},
		{"valid-domain-3", "bücher.example", false, nil, "xn--bcher-kva.example"},

		// single label domain
		{"single-label-1", "localhost", true, ErrSingleLabel, ""},

		// empty label
		{"empty-lbl-1", "foo..bar.com", true, ErrEmptyLabel, ""},
		{"empty-lbl-2", ".bar.com", true, ErrEmptyLabel, ""},

		// hyphens
		{"hyphens-1", "-foo.app", true, ErrIDNAConversion, ""},
		{"hyphens-2", "foo-.-app-", true, ErrIDNAConversion, ""},

		// invalid runes
		{"inv-runes1", "foo_bar.com", true, ErrIDNAConversion, ""},

		// numeric TLD (allowed)
		{"num-tld-1", "example.123", false, nil, "example.123"},
		// punycode round-trip
		{"puny-code-1", "xn--d1acufc.xn--p1ai", false, nil, "xn--d1acufc.xn--p1ai"},

		// label and name lengths
		{"long-label", longLabel, true, ErrLabelTooLong, ""},
		{"long-name", tooLongName, true, ErrDomainTooLong, ""},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			domain, err := ValidateDomain(c.raw)
			if c.wantErr {
				require.ErrorIs(t, err, c.Err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.output, domain)
		})
	}
}
