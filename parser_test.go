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

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		spf     string
		want    []Mechanism
		wantErr bool
	}{
		{name: "minimal -all", spf: "v=spf1 -all", want: []Mechanism{mech(QMinus, "all")}},
		{name: "implicit +all", spf: "v=spf1 all", want: []Mechanism{mech(QPlus, "all")}},
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

func TestTokenizer(t *testing.T) {
	cases := []struct {
		name    string
		spf     string
		want    []string
		wantErr bool
	}{
		{
			name: "minimal -all",
			spf:  "v=spf1 -all",
			want: []string{"-all"},
		},
		{
			name: "uppercase prefix, extra spaces",
			spf:  "  V=SPF1    ip4:203.0.113.0/24   -all ",
			want: []string{"ip4:203.0.113.0/24", "-all"},
		},
		{
			name: "tabs and newlines",
			spf:  "v=spf1\tip4:198.51.100.0/24\r\n-all",
			want: []string{"ip4:198.51.100.0/24", "-all"},
		},
		{
			name:    "no prefix",
			spf:     "-all",
			wantErr: true,
		},
		{
			name:    "prefix but no terms",
			spf:     "v=spf1   ",
			wantErr: true,
		},
		{
			name: "multiple tokens",
			spf:  "v=spf1 a mx ptr ~all",
			want: []string{"a", "mx", "ptr", "~all"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tokenizer(tc.spf)

			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
