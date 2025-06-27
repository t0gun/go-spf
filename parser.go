package spf

import (
	"fmt"
	"net"
	"strings"
)

/* ========= core AST types ========= */

type Qualifier rune

const (
	QPlus  Qualifier = '+'
	QMinus Qualifier = '-'
	QTilde Qualifier = '~'
	QMark  Qualifier = '?'
)

type Modifier struct {
	Name  string // "redirect" / "exp" / anything-else
	Value string // raw RHS (may contain macros)
}

type Mechanism struct {
	Qual   Qualifier
	Kind   string     // "all", "ipv4"
	Net    *net.IPNet // only ipv4/ipv6 set this
	Domain string     // only a mx, include, exists use this
	Mask4  int        //only a/mx when dual CIDR present
	Mask6  int
	Macro  string // only exists and later exp uses this
}

// Record -- A whole SPF record in one place.
type Record struct {
	Mechs    []Mechanism
	Redirect *Modifier // nil or the modifier
	Exp      *Modifier
	Unknown  []Modifier
}

/* ========= public parser entry-point ========= */
// Parse validates the RFC 7208 grammar and returns a slice of Terms.RFC 7208 Section 4.6
// It performs zero DNS or macro expansion; section 5 evaluation lives elsewhere.

func Parse(rawTXT string) (*Record, error) {
	tokens, err := tokenizer(rawTXT)
	if err != nil {
		return nil, err // permerror
	}
	record := &Record{}
	for _, tok := range tokens {
		q, rest := stripQualifier(tok)

		mech, err := parseAll(q, rest)
		if err != nil {
			mech, err = parseIP4(q, rest) // not all try ip4
		}

		if err != nil {
			mech, err = parseIP6(q, rest)
		}

		if err != nil {
			return nil, fmt.Errorf("permerror: %v", err)
		}

		record.Mechs = append(record.Mechs, *mech)

	}
	return record, nil
}

// tokenizer splits the string on ASCII spaces and throws away the version tag
func tokenizer(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "v=spf1") {
		return nil, fmt.Errorf("missing v=spf1")
	}
	// throw away version tag
	fields := strings.Fields(raw)[1:]
	// sanity check
	if len(fields) == 0 {
		return nil, fmt.Errorf("no terms")
	}
	return fields, nil
}

// stripQualifier returns the qualifier (+, -, ~, ?) and the remainder of the token.
// if no qualifier is present, QPlus is implied.
func stripQualifier(tok string) (Qualifier, string) {
	if tok == "" {
		return QPlus, tok
	}
	switch tok[0] {
	case '+', '-', '~', '?':
		return Qualifier(tok[0]), tok[1:]
	default:
		return QPlus, tok
	}
}

func parseAll(q Qualifier, rest string) (*Mechanism, error) {
	if rest != "all" {
		return nil, fmt.Errorf("not all")
	}
	return &Mechanism{Qual: q, Kind: "all"}, nil
}

func parseIP4(q Qualifier, rest string) (*Mechanism, error) {
	if !strings.HasPrefix(rest, "ip4:") {
		return nil, fmt.Errorf("no match")
	}

	cidr := strings.TrimPrefix(rest, "ip4:")

	// If there’s no slash, assume /32 (single host)
	if !strings.ContainsRune(cidr, '/') {
		cidr += "/32"
	}

	ip, netw, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return nil, fmt.Errorf("bad ipcidr %q", cidr) // permanent error
	}

	ones, _ := netw.Mask.Size()
	if ones > 32 { // theoretically impossible after the fix, but keep the guard
		return nil, fmt.Errorf("cidr out of range")
	}

	return &Mechanism{
		Qual: q,
		Kind: "ip4",
		Net:  netw,
	}, nil
}

func parseIP6(q Qualifier, rest string) (*Mechanism, error) {
	if !strings.HasPrefix(rest, "ip6:") {
		return nil, fmt.Errorf("no match")
	}
	cidr := strings.TrimPrefix(rest, "ip6:")

	// if there's no slash, assume /128 (single host)
	if !strings.ContainsRune(cidr, '/') {
		cidr += "/128"
	}
	ip, netw, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() != nil {
		return nil, fmt.Errorf("bad ipcidr %q", cidr) // permanent error
	}

	ones, _ := netw.Mask.Size()
	if ones > 128 {
		return nil, fmt.Errorf("cidr out out of range")
	}

	return &Mechanism{
		Qual: q,
		Kind: "ip6",
		Net:  netw,
	}, nil
}
