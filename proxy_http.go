package proxyclient

import (
	"net/http"
	"net/url"
)

func init() {
	supportProxies["http"] = ProxyHTTP
	supportProxies["https"] = ProxyHTTP
}

func ProxyHTTP(u *url.URL, o *Options) http.RoundTripper {
	tr := CreateTransport(o)
	tr.Proxy = http.ProxyURL(u)

	return tr
}
