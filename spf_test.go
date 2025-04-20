package spf

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseSPF(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tc := []struct {
		txt  string
		want []string
		ok   bool
	}{
		{"v=spf1 ip4:203.0.113.0/24 -all", []string{"ip4:203.0.113.0/24", "-all"}, true},
		{"v=spf2 ip4:203.0.113.0/24 -all", nil, false},
		{"v=SPF1 -all", []string{"-all"}, true},
		{"v=spf1        ipv4:203.0.113.0/24  ~all", []string{"ipv4:203.0.113.0/24", "~all"}, true},
	}

	for _, c := range tc {
		got, err := ParseSPF(c.txt)
		if c.ok {
			assert.Equal(c.want, got)
		}
		if !c.ok {
			require.Error(err)
		}

	}
}
