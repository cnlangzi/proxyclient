package proxyclient

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrUnknownProxy = errors.New("proxyclient: unknown proxy protocol")
)

func New(proxyURL string, options ...Option) (*http.Client, error) {
	opt := &Options{}
	for _, o := range options {
		o(opt)
	}

	c := opt.Client

	if c == nil {
		c = &http.Client{}
	}

	if opt.Transport == nil {
		opt.Transport = &http.Transport{}
	}

	if opt.Timeout > 0 {
		c.Timeout = opt.Timeout
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	f, ok := supportProxies[strings.ToLower(u.Scheme)]
	if !ok {
		return nil, ErrUnknownProxy
	}

	c.Transport = f(u, opt)

	return c, nil
}
