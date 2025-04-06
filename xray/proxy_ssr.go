package xray

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("ssr", ProxySSR)
}

// ProxySSR creates a RoundTripper for SSR proxy
func ProxySSR(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// Start SSR client through Xray
	_, port, err := StartSSR(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start SSR proxy: %w", err)
	}

	// Use SOCKS5 proxy created by Xray
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return proxyclient.ProxySocks5(proxyURL, o)
}
