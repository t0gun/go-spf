package spf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/* ---------- quick helpers ---------- */
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

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		spf     string
		want    []Mechanism
		wantErr bool
	}{
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
