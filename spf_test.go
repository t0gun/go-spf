package spf

import (
	"context"
	"errors"
	"github.com/mailspire/spf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
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

func TestLocalPart(t *testing.T) {
	tc := []struct{ sender, want string }{
		{"alice@example.com", "alice"},
		{"<alice@example.com>", "alice"},
		{"<>", "postmaster"},
		{"", "postmaster"},
	}

	for _, c := range tc {
		t.Run("local parts", func(t *testing.T) {
			got := localPart(c.sender)
			assert.Equal(t, got, c.want)
		})
	}

}

func TestChecker_CheckHost(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")

	tests := []struct {
		name      string
		domain    string
		resolver  *fakeResolver
		wantCode  Result
		wantErr   error
		wantCause error
	}{
		{
			name:      "invalid domain -> none",
			domain:    "localhost",
			wantCode:  None,
			wantCause: parser.ErrSingleLabel,
		},
		{
			name:      "NXDOMAIN -> none",
			domain:    "example.com",
			resolver:  &fakeResolver{err: &net.DNSError{Err: "No such host", Name: "example.com", IsNotFound: true}},
			wantCode:  None,
			wantErr:   ErrNoDNSrecord,
			wantCause: ErrNoDNSrecord,
		},
		{
			name:      "temporary DNS error -. TempError",
			domain:    "example.com",
			resolver:  &fakeResolver{err: &net.DNSError{Err: "timeout", Name: "example.com", IsTemporary: true}},
			wantCode:  TempError,
			wantCause: ErrTempfail,
		},
		{
			name:      "permanent DNS error -> PermError",
			domain:    "example.com",
			resolver:  &fakeResolver{err: errors.New("perm failure")},
			wantCause: ErrPermfail,
			wantCode:  PermError,
		},
		{
			name:      "multiple SPF records -> PermError",
			domain:    "example.com",
			resolver:  &fakeResolver{txts: []string{"v=spf1 a", "v=spf1 mx"}},
			wantCode:  PermError,
			wantCause: ErrMultipleSPF,
		},
		{
			name:     "no SPF record → zero result",
			domain:   "example.com",
			resolver: &fakeResolver{txts: []string{"some txt"}},
			wantCode: Result(""),
		},

		{
			name:     "context canceled propagates",
			domain:   "example.com",
			resolver: &fakeResolver{err: context.Canceled},
			wantErr:  context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := NewChecker(NewCustomDNSResolver(tc.resolver))
			res, err := ch.CheckHost(context.Background(), ip, tc.domain, "user@example.com")
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.wantCode, res.Code)

			if tc.wantCause != nil {
				require.ErrorIs(t, res.Cause, tc.wantCause)
			} else {
				assert.Nil(t, res.Cause)
			}
		})
	}
}

func TestChecker_EvaluateAll(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")

	cases := []struct {
		name   string
		record string
		want   Result
	}{
		{"fail all", "v=spf1 -all", Fail},
		{"softfail all", "v=spf1 ~all", SoftFail},
		{"pass all", "v=spf1 +all", Pass},
		{"implicit pass all", "v=spf1 all", Pass},
		{"neutral all", "v=spf1 ?all", Neutral},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := NewChecker(NewCustomDNSResolver(&fakeResolver{txts: []string{tc.record}}))
			res, err := ch.CheckHost(context.Background(), ip, "example.com", "user@example.com")
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.Code)
		})
	}
}

func TestChecker_EvaluateIP4(t *testing.T) {
	cases := []struct {
		name   string
		ip     string
		record string
		want   Result
	}{
		{"match pass", "203.0.113.5", "v=spf1 ip4:203.0.113.0/24 -all", Pass},
		{"match fail", "192.0.2.10", "v=spf1 -ip4:192.0.2.0/24 +all", Fail},
		{"no match -> all", "198.51.100.1", "v=spf1 ip4:203.0.113.0/24 -all", Fail},
		{"ipv6 skip -> all", "2001:db8::1", "v=spf1 ip4:203.0.113.0/24 ~all", SoftFail},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			ch := NewChecker(NewCustomDNSResolver(&fakeResolver{txts: []string{tc.record}}))
			res, err := ch.CheckHost(context.Background(), ip, "example.com", "user@example.com")
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.Code)
		})
	}
}
