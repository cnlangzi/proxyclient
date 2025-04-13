package proxyclient

import (
	"net"
	"net/url"
	"regexp"
	"strings"
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
	return IsIP(s) && IsDomain(s)
}

func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

var regexDomain = regexp.MustCompile(`^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func IsDomain(s string) bool {
	if !regexDomain.MatchString(strings.ToLower(s)) {
		return false
	}

	ips, err := net.LookupIP(s)
	if err != nil {
		return false
	}

	return len(ips) > 0
}
