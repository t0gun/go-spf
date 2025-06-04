package spf

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
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

