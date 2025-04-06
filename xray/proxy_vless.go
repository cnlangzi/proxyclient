package xray

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("vless", ProxyVless)
}

func ProxyVless(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	_, port, err := StartVless(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start VLESS proxy: %w", err)
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return proxyclient.ProxySocks5(proxyURL, o)
}
