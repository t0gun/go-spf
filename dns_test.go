package spf

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFilterSPF(t *testing.T) {
	tc := []struct {
		txts  []string
		want  string
		isErr bool
	}{
		{[]string{"v=spf1 -all", "v=spf2 a -all", " v=spf10 a ~all "}, "v=spf1 -all", false},
		{[]string{"v=spf1", "v=spf2 ipv4:192.168.0/24"}, "v=spf1", false},
		{[]string{"v=spf1 -all", "v=spf1 a -all", " v=spf10 a ~all "}, "v=spf1 -all", true},
	}

	for _, c := range tc {
		got, err := filterSPF(c.txts)
		if c.isErr {
			require.ErrorIs(t, err, ErrMultipleSPF)

		} else {
			assert.Equal(t, c.want, got)
			require.NoError(t, err)
		}
	}
}
