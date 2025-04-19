package proxyclient

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

type FuncParser func(u *url.URL) (URL, error)

var parsers = make(map[string]FuncParser)

func RegisterParser(proto string, f FuncParser) {
	parsers[proto] = f
}

type URL interface {
	Raw() *url.URL
	Opaque() string
	Protocol() string
	Host() string
	Port() string
	User() string
	Password() string
}

type stdURL struct {
	url.URL
}

func (u *stdURL) Raw() *url.URL {
	return &u.URL
}

func (u *stdURL) Opaque() string {
	return u.URL.Opaque
}

func (u *stdURL) Host() string {
	return u.URL.Hostname()
}
func (u *stdURL) Port() string {
	return u.URL.Port()
}

func (u *stdURL) Protocol() string {
	return u.URL.Scheme
}
func (u *stdURL) User() string {
	if u.URL.User == nil {
		return ""
	}
	return u.URL.User.Username()
}
func (u *stdURL) Password() string {
	if u.URL.User == nil {
		return ""
	}
	passwd, _ := u.URL.User.Password()
	return passwd
}

func ParseURL(u string) (URL, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	parser, ok := parsers[parsedURL.Scheme]
	if ok {
		return parser(parsedURL)
	}

	if IsHost(parsedURL.Hostname()) {
		return &stdURL{*parsedURL}, nil
	}

	return nil, ErrInvalidHost
}

func IsHost(s string) bool {
	return IsIP(s) || IsDomain(s)
}

func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// Regex for standard domains and many non-standard TLDs including:
// - Numeric TLDs (.0, .123)
// - Single character TLDs (.x, .q)
// - Hyphenated TLDs (.my-domain)
// - Multiple levels (.co.jp, etc.)
var regexDomain = regexp.MustCompile(`^([a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-_]{1,}$`)

func IsDomain(s string) bool {
	// First check if the domain is in ASCII format
	if regexDomain.MatchString(strings.ToLower(s)) {
		return true
	}

	// Additional validation for IDN domains
	// Check for invalid control characters
	for _, r := range s {
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			// Control characters are not allowed in domain names
			return false
		}
	}

	// Check for invalid mixed directional text within the same label
	parts := strings.Split(s, ".")
	for _, part := range parts {
		if containsMixedDirectionalText(part) {
			return false
		}
	}

	// Try to handle IDN (Internationalized Domain Names)
	punycode, err := idna.ToASCII(s)
	if err != nil {
		return false
	}

	// Check the Punycode version against the regex
	return regexDomain.MatchString(strings.ToLower(punycode))
}

// containsMixedDirectionalText checks if a string contains both RTL and LTR characters
// within the same domain label, which is typically invalid
func containsMixedDirectionalText(s string) bool {
	hasRTL := false
	hasLTR := false

	for _, r := range s {
		// Arabic, Hebrew and other RTL script ranges
		if (r >= 0x0590 && r <= 0x08FF) || (r >= 0xFB1D && r <= 0xFDFF) || (r >= 0xFE70 && r <= 0xFEFF) {
			hasRTL = true
		}
		// Basic Latin letters (not digits or symbols)
		if r >= 0x0041 && r <= 0x007A {
			hasLTR = true
		}
		// If we have both directions in the same label, it's not valid
		if hasRTL && hasLTR {
			return true
		}
	}
	return false
}
