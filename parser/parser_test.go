package parser

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- quick helpers ---------- //
func allMech(q Qualifier, kind string) Mechanism {
	return Mechanism{Qual: q, Kind: kind}
}

func ip4Mech(q Qualifier, cidr string) Mechanism {
	_, n, _ := net.ParseCIDR(cidr)
	return Mechanism{Qual: q, Kind: "ip4", Net: n}
}

func ip6Mech(q Qualifier, cidr string) Mechanism {
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
	return Mechanism{Qual: q, Kind: "exists", Domain: domain, Macro: hasMacro}
}

func IncMech(q Qualifier, domain string, hasMacro bool) Mechanism {
	return Mechanism{Qual: q, Domain: domain, Kind: "include", Macro: hasMacro}
}

func mod(modifier string) *Modifier {
	before, after, _ := strings.Cut(modifier, "=")
	return &Modifier{Name: before, Value: after, Macro: strings.ContainsRune(after, '%')}
}

func TestParse(t *testing.T) {
	ass := assert.New(t)
	req := require.New(t)
	cases := []struct {
		name         string
		spf          string
		wantMech     []Mechanism
		wantRedirect *Modifier
		wantExp      *Modifier
		wantUnknown  []Modifier
		wantErr      bool
	}{
		// Ipv4 mechanism tests
		{
			name:     "ip4 then -all",
			spf:      "v=spf1 ip4:203.0.113.0/24 -all",
			wantMech: []Mechanism{ip4Mech(QPlus, "203.0.113.0/24"), allMech(QMinus, "all")},
		},

		{
			name:     "implicit +all",
			spf:      "v=spf1 all",
			wantMech: []Mechanism{allMech(QPlus, "all")}},

		{
			name:    "bad cidr ip4",
			spf:     "v=spf1 ip4:203.0.113.0/99 -all",
			wantErr: true,
		},
		{
			name:     "ip4 with no mask then ~all",
			spf:      "v=spf1 +ip4:203.0.113.23 ~all",
			wantMech: []Mechanism{ip4Mech(QPlus, "203.0.113.23/32"), allMech(QTilde, "all")},
		},

		{
			name:     "ip6 and ip4 then -all",
			spf:      "v=spf1 ip6:2001:db8::/32 ip4:203.0.113.0/24 -all",
			wantMech: []Mechanism{ip6Mech(QPlus, "2001:db8::/32"), ip4Mech(QPlus, "203.0.113.0/24"), allMech(QMinus, "all")},
		},

		{
			name:     "implicit /128 host",
			spf:      "v=spf1 ip6:2001:db8::1 -all",
			wantMech: []Mechanism{ip6Mech(QPlus, "2001:db8::1/128"), allMech(QMinus, "all")},
		},
		{
			name:    "bad ipv6 cidr",
			spf:     "v=spf1 ip6:2001:db8::/200 -all",
			wantErr: true,
		},

		{
			name:     "bare a defaults with all",
			spf:      "v=spf1 a -all",
			wantMech: []Mechanism{aMech(QPlus, "", -1, -1), allMech(QMinus, "all")},
		},
		{
			name:     "a with /24",
			spf:      "v=spf1 a/24 -all",
			wantMech: []Mechanism{aMech(QPlus, "", 24, -1), allMech(QMinus, "all")},
		},
		{
			name:     "a explicit domain dual masks",
			spf:      "v=spf1 a:mail.example.com/24/64 -all",
			wantMech: []Mechanism{aMech(QPlus, "mail.example.com", 24, 64), allMech(QMinus, "all")},
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
			name:     "mx with masks",
			spf:      "v=spf1 mx/24 -all",
			wantMech: []Mechanism{mxMech(QPlus, "", 24, -1), allMech(QMinus, "all")},
		},

		{
			name:     "mx explicit domain, dual masks",
			spf:      "v=spf1 mx:mail.example.org/24/64 -all",
			wantMech: []Mechanism{mxMech(QPlus, "mail.example.org", 24, 64), allMech(QMinus, "all")},
		},
		{
			name:    "mx bad v6 mask",
			spf:     "v=spf1 mx/124/129 ~all",
			wantErr: true,
		},
		{
			name:     "bare ptr then -all",
			spf:      "v=spf1 ptr -all",
			wantMech: []Mechanism{ptrMech(QPlus, "", false), allMech(QMinus, "all")},
		},
		{
			name:     "ptr explicit domain with hard all",
			spf:      "v=spf1 ~ptr:example.com -all",
			wantMech: []Mechanism{ptrMech(QTilde, "example.com", false), allMech(QMinus, "all")},
		},
		{
			name:     "ptr containing macro then -all",
			spf:      "v=spf1 ptr:%{d} -all",
			wantMech: []Mechanism{ptrMech(QPlus, "%{d}", true), allMech(QMinus, "all")},
		},
		{
			name:     "bare ptr with no domain and -all",
			spf:      "v=spf1 ptr -all",
			wantMech: []Mechanism{ptrMech(QPlus, "", false), allMech(QMinus, "all")},
		},

		{
			name:     "exists with macro and -all",
			spf:      "v=spf1  exists:%{i}._spf.example.com -all",
			wantMech: []Mechanism{existMech(QPlus, "%{i}._spf.example.com", true), allMech(QMinus, "all")},
		},

		{
			name:    "exists with with no value",
			spf:     "v=spf1 ip4:192.168.0/24 exists -all",
			wantErr: true,
		},
		{
			name:     "include then all",
			spf:      "v=spf1 include:_spf.include.com -all",
			wantMech: []Mechanism{IncMech(QPlus, "_spf.include.com", false), allMech(QMinus, "all")},
		},
		{
			name: "2 includes then all",
			spf:  "v=spf1 include:sendgrid.net -include:servers.mcsv.net -all",
			wantMech: []Mechanism{IncMech(QPlus, "sendgrid.net", false),
				IncMech(QMinus, "servers.mcsv.net", false), allMech(QMinus, "all")},
		},
		{
			name:         "spf with include and redirect modifier",
			spf:          "v=spf1 include:_spf.inc.com -all redirect=otherdomain.com",
			wantMech:     []Mechanism{IncMech(QPlus, "_spf.inc.com", false), allMech(QMinus, "all")},
			wantRedirect: mod("redirect=otherdomain.com"),
		},
		{
			name:     "spf with ip4 and exp modifier",
			spf:      "v=spf1 ip4:192.0.2.0/24 -all exp=%{i}._spf.explain.com",
			wantMech: []Mechanism{ip4Mech(QPlus, "192.0.2.0/24"), allMech(QMinus, "all")},
			wantExp:  mod("exp=%{i}._spf.explain.com"),
		},
		{
			name:        "spf with unknown modifier preserved",
			spf:         "v=spf1 a -all foo=bar",
			wantMech:    []Mechanism{aMech(QPlus, "", -1, -1), allMech(QMinus, "all")},
			wantUnknown: []Modifier{*mod("foo=bar")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Parse(tc.spf)

			if tc.wantErr {
				req.Error(err)
				return
			}
			req.NoError(err)
			ass.Equal(tc.wantMech, rec.Mechs)
			ass.Equal(tc.wantRedirect, rec.Redirect)
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
