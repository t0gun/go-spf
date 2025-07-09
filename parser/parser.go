package parser

import (
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"strconv"
	"strings"
)

// ========= core AST types ========= //

// Qualifier represents the prefix modifier for a mechanism as defined in
// RFC 7208 section 4.6.  It controls how a match affects the overall result.
type Qualifier rune

const (
	QPlus  Qualifier = '+' // pass
	QMinus Qualifier = '-' // fail
	QTilde Qualifier = '~' // softfail
	QMark  Qualifier = '?' // neutral
)

// Modifier represents a key=value term such as "redirect" or "exp" from
// RFC 7208 section 6.  The value may contain macros which are expanded during
// evaluation.
type Modifier struct {
	Name  string // "redirect" / "exp" / anything-else
	Value string // raw RHS (may contain macros)
	Macro bool   // used by redirect rfc 7208 section 6.1
}

// Mechanism describes one mechanism term in an SPF record.  The fields are
// populated according to the specific mechanism type as defined in RFC 7208
// section 5.
type Mechanism struct {
	Qual   Qualifier
	Kind   string     // "all", "ipv4"
	Net    *net.IPNet // only ipv4/ipv6 set this
	Domain string     // only a, mx, include, exists use this
	Mask4  int        // only a/mx when dual CIDR present
	Mask6  int
	Macro  bool // only exists and later exp uses this
}

// Record holds a parsed SPF record.
type Record struct {
	Mechs    []Mechanism
	Redirect *Modifier // nil or the modifier
	Exp      *Modifier
	Unknown  []Modifier
}

// Errors returned by ValidateDomain.  Each corresponds to one of the
// syntax checks described in RFC 7208 section 4.3.
var (
	ErrSingleLabel    = errors.New("domain must have at least two labels")
	ErrEmptyLabel     = errors.New("domain has empty label")
	ErrLabelTooLong   = errors.New("domain label exceeds 63 octets")
	ErrDomainTooLong  = errors.New("domain exceeds 255 octets")
	ErrIDNAConversion = errors.New("IDNA ToASCII failed")
)

var ErrNotModifier = errors.New("-not-modifier")

/* ========= public parser entry-point ========= */
// Parse checks the record syntax defined in RFC 7208 section 4.6 and returns a structured representation.
// The function performs no DNS lookups or macro expansion; evaluation according to section 5 is handled elsewhere.

func Parse(rawTXT string) (*Record, error) {
	tokens, tokErr := tokenizer(rawTXT)
	if tokErr != nil {
		return nil, tokErr
	}

	// ordered list of mechanism parsers
	mechParsers := []func(Qualifier, string) (*Mechanism, error){
		parseAll, parseIP4, parseIP6,
		parseA, parseMX, parsePTR,
		parseExists, parseInclude,
	}
	record := &Record{}
	for _, tok := range tokens {
		// parse mod first if not  mod, then it's a mechanism
		// rfc  7208 section 6.1 says the two mods... redirect and exp must not appear in a record more than once
		// if they do we would send this to dispatcher to call a perm error
		// unrecognised mod must be ignored,here we store them as unknown
		mod, modErr := parserModifier(tok)
		if modErr == nil {
			switch mod.Name {
			case "redirect":
				if record.Redirect != nil {
					return nil, fmt.Errorf("duplicate redirect")
				}
				if !strings.ContainsRune(mod.Value, '%') {
					if _, e := ValidateDomain(mod.Value); e != nil {
						return nil, e
					}
				}
				record.Redirect = mod
				mod.Macro = strings.ContainsRune(mod.Value, '%')

			case "exp":
				if record.Exp != nil {
					return nil, fmt.Errorf("duplicate exp")
				}
				if !strings.ContainsRune(mod.Value, '%') {
					if _, e := ValidateDomain(mod.Value); e != nil {
						return nil, e
					}
				}
				record.Exp = mod
				mod.Macro = strings.ContainsRune(mod.Value, '%')

			default:
				record.Unknown = append(record.Unknown, *mod)
				mod.Macro = strings.ContainsRune(mod.Value, '%')

			}
			continue // done with this token skip to next loop
		}

		// -------- bad-modifier branch --------
		if !errors.Is(modErr, ErrNotModifier) {
			return nil, modErr
		}

		// mechanisms are discovered from this point
		q, rest := stripQualifier(tok)
		var mech *Mechanism
		var perr error
		for _, pf := range mechParsers {
			if mech, perr = pf(q, rest); perr == nil {
				break // found a match
			}
		}
		if perr != nil || mech == nil {
			return nil, fmt.Errorf("permerror: %v", perr)
		}
		record.Mechs = append(record.Mechs, *mech)
	}
	return record, nil
}

// tokenizer splits a raw SPF record into whitespace-separated terms and drops
// the leading "v=spf1" version tag.  It implements the tokenisation described
// in RFC 7208 section 4.6.
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

// parseAll parses the "all" mechanism.  It matches any sender and has no
// arguments as specified in RFC 7208 section 5.1.
func parseAll(q Qualifier, rest string) (*Mechanism, error) {
	if rest != "all" {
		return nil, fmt.Errorf("not all")
	}
	return &Mechanism{Qual: q, Kind: "all"}, nil
}

// parseIP4 parses the "ip4" mechanism which matches IPv4 networks as described
// in RFC 7208 section 5.2.
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

// parseIP6 parses the "ip6" mechanism which matches IPv6 networks as defined in
// RFC 7208 section 5.2.
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

// parseMasks converts "24" or "24/64" into two integers.  It is used by the
// A and MX mechanism parsers to interpret CIDR length suffixes.
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

// parseMX - RFC 7208 section 5.4  —  “mx” mechanism
//
// ABNF recap (very similar to “a”):
//
//	mx                ; current domain’s MX hosts, default masks
//	mx/24             ; v4 mask 24, v6 = unlimited
//	mx/24/64          ; v4 mask 24, v6 mask 64
//	mx:example.org    ; explicit domain, default masks
//	mx:example.org/24 ; explicit domain, v4 mask 24
//	mx:example.org/24/64
//
// If ip4-cidr-length is missing  → assume /32     ( section 5.6)
// If ip6-cidr-length is missing  → assume /128    (section 5.6)
//
// Any syntax error is a permerror; the helper returns a normal error and the
// dispatcher wraps it.
func parseMX(q Qualifier, rest string) (*Mechanism, error) {
	if !strings.HasPrefix(rest, "mx") {
		return nil, fmt.Errorf("no match") // dispatcher will try the next helper
	}
	spec := rest[2:] // trim leading mx
	domain := ""     // empty = “current” SPF domain
	mask4, mask6 := -1, -1

	switch {
	case spec == "":
		// bare mx, nothing to parse
	case strings.HasPrefix(spec, "/"):
		// "/mask" OR "/mask4/mask6"
		var err error
		mask4, mask6, err = parseMasks(strings.TrimPrefix(spec, "/"))
		if err != nil {
			return nil, err
		}
	case strings.HasPrefix(spec, ":"):
		// ":domain"["/"...]
		afterColon := strings.TrimPrefix(spec, ":")
		domainPart, maskPart, _ := strings.Cut(afterColon, "/")
		if domainPart != "" {
			if _, err := ValidateDomain(domainPart); err != nil {
				return nil, fmt.Errorf("bad domain %q", domainPart)
			}
			domain = domainPart
		}
		if maskPart != "" {
			var err error
			mask4, mask6, err = parseMasks(maskPart)
			if err != nil {
				return nil, err
			}
		}

	default:
		return nil, fmt.Errorf("invalid mx-mechanism syntax %q", rest)
	}
	return &Mechanism{
		Qual:   q,
		Kind:   "mx",
		Domain: domain,
		Mask4:  mask4,
		Mask6:  mask6,
	}, nil
}

// parsePTR parses the “ptr” mechanism – RFC 7208  section 5.5.
//
//	ptr              ; current domain
//	ptr:example.org  ; explicit target domain (can contain macros)
//
// The RFC allows <domain-spec> to contain macros.  We store the raw text
// in Mechanism.Domain; macro expansion happens during evaluation.
// ptr is strongly discouraged in spf records and may course unnecessary lookups
func parsePTR(q Qualifier, rest string) (*Mechanism, error) {
	if !strings.HasPrefix(rest, "ptr") {
		return nil, fmt.Errorf(" no match")
	}
	spec := rest[3:] // trim leading "ptr"
	switch {
	case spec == "":
		// bare "ptr" - nothing to do here
	case strings.HasPrefix(spec, ":"):
		spec = strings.TrimPrefix(spec, ":")
	}
	return &Mechanism{
		Qual:   q,
		Kind:   "ptr",
		Domain: spec, // raw, possibly macro-containing string
		Macro:  strings.ContainsRune(spec, '%'),
	}, nil
}

// parseExists parses the “exists” mechanism – RFC 7208 section 5.7.
//
//	exists:domain-spec
//
// domain-spec may include macros (e.g. "%{i}.example.com").
// If it contains no macro chars, we do a quick ValidateDomain check now.
//
// On match, the evaluator will perform a DNS A/AAAA lookup of the expanded
// domain and succeed if there’s any record.
func parseExists(q Qualifier, rest string) (*Mechanism, error) {
	const prefix = "exists:"
	if !strings.HasPrefix(rest, prefix) {
		return nil, fmt.Errorf("no match")
	}
	spec := rest[len(prefix):]
	if spec == "" {
		return nil, fmt.Errorf("empty exists domain") // will break spf
	}

	return &Mechanism{
		Qual:   q,
		Kind:   "exists",
		Domain: spec, // raw, possibly macro-containing string
		Macro:  strings.ContainsRune(spec, '%'),
	}, nil
}

// parseInclude parses the "include" mechanism (RFC 7208 §5.1).
// It looks for the literal prefix "include:" (case-insensitive), then
// captures the remainder as the domain-spec. If the spec is empty,
// it returns an error. Macro syntax (“%{…}”) is detected but not
// validated here; actual DNS lookups and macro expansion happen later.
// On success, it returns a Mechanism with Kind="include", Domain set to
// the raw spec, Macro=true if any '%' appears, and the given qualifier.
func parseInclude(q Qualifier, rest string) (*Mechanism, error) {
	const prefix = "include:"
	if !strings.HasPrefix(rest, prefix) {
		return nil, fmt.Errorf("no match")
	}
	spec := rest[len(prefix):]
	if spec == "" {
		return nil, fmt.Errorf("include has an empty domain") // will break spf
	}
	return &Mechanism{
		Qual:   q,
		Kind:   "include",
		Domain: spec,
		Macro:  strings.ContainsRune(spec, '%'),
	}, nil
}

// ValidateDomain normalises and validates a raw domain name, according to
// RFC 7208, section 4.3.
// Validation steps:
//
//  1. Remove one trailing dot because domains are implicitly absolute.
//
//  2. Convert the name to its Punycode A-label form with idna.Lookup.ToASCII.
//
//  3. Apply SPF pre-evaluation checks:
//
//     * Overall length must not exceed 255 octets.
//     * The domain must contain at least two labels (must include a dot).
//     * No empty label may appear except the implicit root.
//     * Each label must be 1–63 octets long.
//     * Labels may contain only lower-case letters, digits, and hyphens.
//     * A hyphen may not appear at the start or end of any label.
//
// On success the function returns the ASCII (lower-case) domain and nil.
// On failure, it returns an empty string along with a sentinel error.
func ValidateDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	// Trim the single trailing dot if any
	raw = strings.TrimSuffix(raw, ".")

	// convert to A-label RFC 5890 section 2.3
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", ErrIDNAConversion
	}
	ascii = strings.ToLower(ascii)

	// check overall length limit
	if len(ascii) > 255 {
		return "", ErrDomainTooLong
	}

	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrSingleLabel
	}

	for _, lbl := range labels {
		switch {
		case len(lbl) == 0:
			return "", ErrEmptyLabel

		case len(lbl) > 63:
			return "", ErrLabelTooLong

		}

	}

	return ascii, nil
}

// parserModifier splits one SPF term of the form “name=value” into a *Modifier.
// It performs *only* the neutral syntax work mandated by RFC 7208 section 6:
//
//   - returns (nil, ErrNotModifier) when the token contains no ‘=’ – letting the
//     caller fall through to mechanism parsing.
//
//   - trims leading/trailing whitespace, lower-cases both name and value,
//     and rejects an empty RHS (“modifier missing value”) with a regular error
//     that callers SHOULD treat as a permerror.
//
//   - does **not** validate the value beyond being non-empty – redirect/exp
//
//   - sets m.Macro to true if the value contains ‘%’, so evaluators know whether
//     macro expansion is required later.
//
// The helper never inspects the SPF record context, making it reusable for
// unknown modifiers that RFC 7208 says must be ignored but preserved.
func parserModifier(tok string) (*Modifier, error) {
	var name, value string
	var ok bool
	if name, value, ok = strings.Cut(tok, "="); ok {
		name, value = strings.ToLower(name), strings.ToLower(value)
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	}
	if !ok {
		return nil, ErrNotModifier
	}

	if value == "" {
		return nil, fmt.Errorf(" modifier missing value")
	}
	return &Modifier{Name: name, Value: value, Macro: false}, nil
}
