package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ========= core AST types ========= //

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
		return nil, err
	}

	// ordered list of mechanism parsers
	mechParsers := []func(Qualifier, string) (*Mechanism, error){
		parseAll, parseIP4, parseIP6, parseA,
	}
	record := &Record{}
	for _, tok := range tokens {
		q, rest := stripQualifier(tok)

		var mech *Mechanism
		var perr error
		for _, pf := range mechParsers {
			if mech, perr = pf(q, rest); perr == nil {
				break // found a match
			}
		}
		if perr != nil {
			return nil, fmt.Errorf("permerror: %v", perr)
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

// parseA parses the “a” mechanism.
//
// Grammar recap (RFC 7208  Section 5.3 + Section 5.6):
//
//	a                ; current domain, default masks
//	a/24             ; v4 mask = 24, v6 = unlimited
//	a/24/64          ; v4 = 24, v6 = 64
//	a:mail.example   ; explicit domain, default masks
//	a:mail.example/24/64
//
// If a slash segment is missing, defaults are /32 for IPv4 and /128 for IPv6.
// Any syntax violation is a permerror (we return a regular error and let the
// caller wrap it as permerror).
func parseA(q Qualifier, rest string) (*Mechanism, error) {
	if !strings.HasPrefix(rest, "a") {
		return nil, fmt.Errorf("no match") // dispatcher will try the next helper
	}
	// chop off leading "a"
	spec := rest[1:]       // could be "", ":domain", "/mask", ":domain/...", etc.
	domain := ""           // empty => “current domain”
	mask4, mask6 := -1, -1 // -1 means “not specified”

	switch {
	case spec == "":
	// bare "a" nothing more to parse

	case strings.HasPrefix(spec, "/"):
		// "/mask" or "/mask4/mask6" with no explicit domain
		var err error
		mask4, mask6, err = parseMasks(strings.TrimPrefix(spec, "/"))
		if err != nil {
			return nil, err
		}
	case strings.HasPrefix(spec, ":"):
		// ":domain" [ "/" ... ]
		afterColon := strings.TrimPrefix(spec, ":")
		// split once: left = domain, right (optional) = "mask" or "mask4/mask6"
		domainPart, maskPart, _ := strings.Cut(afterColon, "/")
		// check domain part
		if domainPart != "" {
			if _, err := ValidateDomain(domainPart); err != nil {
				return nil, fmt.Errorf("bad a record domain %q", domainPart)
			}
			domain = domainPart
		}
		// check if mask exists
		if maskPart != "" {
			var err error
			mask4, mask6, err = parseMasks(maskPart)
			if err != nil {
				return nil, err
			}
		}

	default:
		// anything else is illegal — e.g. "afoobar" — let caller permerror
		return nil, fmt.Errorf("invalid a-mechanism syntax %q", rest)

	}
	return &Mechanism{
		Qual:   q,
		Kind:   "a",
		Domain: domain, // "" = current domain
		Mask4:  mask4,
		Mask6:  mask6,
	}, nil
}

// parseMasks convert "24" or "24/64" into two ints.
// input string examples :
//
//	"24"       -> mask4=24 mask6=-1
//	"24/64"    -> mask4=24 mask6=64
//
// Returns error if:
//   - non-decimal
//   - /0 CIDR that exceeds bounds (0–32, 0–128)
//   - more than two slash-separated parts
func parseMasks(maskstr string) (mask4, mask6 int, err error) {
	toInt := func(s string, max int) (int, error) {
		n, e := strconv.Atoi(s)
		if e != nil || n < 0 || n > max {
			return 0, fmt.Errorf("cidr out of range")
		}
		return n, nil
	}

	parts := strings.Split(maskstr, "/")
	switch len(parts) {
	case 1:
		mask4, err = toInt(parts[0], 32)
		mask6 = -1
	case 2:
		mask4, err = toInt(parts[0], 32)
		if err != nil {
			return
		}
		mask6, err = toInt(parts[1], 128)

	default:
		err = fmt.Errorf("too many / segments in mask")
	}
	return
}
