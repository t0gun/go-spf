package spf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetSenderDomain(t *testing.T) {
	t.Parallel()
	tc := []struct {
		sender string
		domain string
	}{
		{"apps@gmail.com", "gmail.com"},
		{"apps@yahoo.com", "yahoo.com"},
	}

	for _, c := range tc {
		got, ok := getSenderDomain(c.sender)
		assert.Equal(t, c.domain, got)
		assert.True(t, ok)
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

	assert := assert.New(t)
	require := require.New(t)
	tc := []struct {
		raw     string
		wantErr bool
		Err     error
		output  string
	}{
		// valid domain names
		{"example.com", false, nil, "example.com"},
		{"example.ORG.", false, nil, "example.org"},
		{"bücher.example", false, nil, "xn--bcher-kva.example"},

		// single label domain
		{"localhost", true, ErrSingleLabel, ""},

		// empty label
		{"foo..bar.com", true, ErrEmptyLabel, ""},
		{".bar.com", true, ErrEmptyLabel, ""},

		// hyphens
		{"-foo.app", true, ErrHyphenPosition, ""},
		{"foo-.app", true, ErrHyphenPosition, ""},

		// invalid runes
		{"foo_bar.com", true, ErrInvalidRune, ""},

		// numeric TLD (allowed)
		{"example.123", false, nil, "example.123"},
		// punycode round-trip
		{"xn--d1acufc.xn--p1ai", false, nil, "xn--d1acufc.xn--p1ai"},

		// label and name lengths
		{longLabel, true, ErrLabelTooLong, ""},
		{tooLongName, true, ErrDomainTooLong, ""},
	}

	for _, c := range tc {
		domain, err := ValidateDomain(c.raw)
		if c.wantErr {
			require.ErrorIs(err, c.Err)
			continue // skip to the next iteration to avoid failure
		}
		require.NoError(err)
		assert.Equal(c.output, domain)
	}
}
