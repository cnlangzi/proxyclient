package proxyclient

import (
	"net/url"
)

type FuncParser func(u *url.URL) (URL, error)

var parsers = make(map[string]FuncParser)

func RegisterParser(proto string, f FuncParser) {
	parsers[proto] = f
}

type URL interface {
	Raw() *url.URL
	Host() string
	Port() string
}

type stdURL struct {
	url.URL
}

func (u *stdURL) Raw() *url.URL {
	return &u.URL
}

func (u *stdURL) Host() string {
	return u.URL.Host
}
func (u *stdURL) Port() string {
	return u.URL.Port()
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

	return &stdURL{*parsedURL}, nil
}
