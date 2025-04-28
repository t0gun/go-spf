package spf

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

// fake Resolver implements TXT resolver
type fakeResolver struct {
	txts []string
	err  error
}

func (f *fakeResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return f.txts, f.err
}

func TestGetSPFRecord_ErrorsAndFiltering(t *testing.T) { //nolint:paralleltest
	tc := []struct {
		name         string
		fakeResolver *fakeResolver
		wantSPF      string
		wantErr      error
	}{
		{
			name:         "NXDOMAIN → ErrNoDNSrecord",
			fakeResolver: &fakeResolver{nil, &net.DNSError{Err: "no such host", Name: "foo", IsNotFound: true}},
			wantErr:      ErrNoDNSrecord,
		},
		{
			name:         "Temporary DNS → ErrTempfail",
			fakeResolver: &fakeResolver{nil, &net.DNSError{Err: "simulated temp failure", Name: "network down", IsTemporary: true}},
			wantErr:      ErrTempfail,
		},
		{
			name:         "Other DNS error → ErrPermfail",
			fakeResolver: &fakeResolver{nil, errors.New("network down")},
			wantErr:      ErrPermfail,
		},
		{
			name:         "No SPF record on existing domain → empty, no error",
			fakeResolver: &fakeResolver{[]string{"some txt", "other txt"}, nil},
			wantSPF:      "",
			wantErr:      nil,
		},
		{
			name:         "One valid SPF record → return it ",
			fakeResolver: &fakeResolver{[]string{"v=spf1 mx -all", "txt other"}, nil},
			wantSPF:      "v=spf1 mx -all",
			wantErr:      nil,
		},
		{
			name:         "Multiple SPF records → ErrMultipleSPF",
			fakeResolver: &fakeResolver{[]string{"v=spf1 a -all", "v=spf1 mx -all"}, nil},
			wantErr:      ErrMultipleSPF,
		},
	}

	for _, c := range tc { //nolint:paralleltest
		t.Run(c.name, func(t *testing.T) {
			dr := NewCustomDNSResolver(c.fakeResolver)
			// ctx with timeout to exercise ctx flow
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()

			spf, err := dr.GetSPFRecord(ctx, "example.com")
			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.wantSPF, spf)

		})

	}

}

func TestFilterSPF(t *testing.T) {
	tc := []struct {
		name      string
		txts      []string
		wantSPF   string
		wantError bool
	}{
		{"valid spf -all", []string{"v=spf1 -all", "v=spf2 a -all", " v=spf10 a ~all "}, "v=spf1 -all", false},
		{"valid spf version only", []string{"v=spf1", "v=spf2 ipv4:192.168.0/24"}, "v=spf1", false},
		{"", []string{"v=spf1 -all", "v=spf1 a -all", " v=spf10 a ~all "}, "v=spf1 -all", true},
	}

	for _, c := range tc { //nolint:paralleltest
		t.Run(c.name, func(t *testing.T) {
			got, err := filterSPF(c.txts)
			if c.wantError {
				require.ErrorIs(t, err, ErrMultipleSPF)

				return

			}
			assert.Equal(t, c.wantSPF, got)
			require.NoError(t, err)

		})
	}
}
