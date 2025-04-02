package xray

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("trojan", ProxyTrojan)
}

// ProxyTrojan creates a RoundTripper for Trojan proxy
func ProxyTrojan(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// Start Trojan client through Xray
	_, port, err := StartTrojan(u.String(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start Trojan proxy: %w", err)
	}

	// Use SOCKS5 proxy created by Xray
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return proxyclient.ProxySocks5(proxyURL, o)
}
