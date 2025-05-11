package xray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("ssr", DialSSR)
}

// ProxySSR creates a RoundTripper for SSR proxy
// func ProxySSR(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
// 	// Start SSR client through Xray
// 	_, port, err := StartSSR(u, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start ssr proxy: %w", err)
// 	}

// 	// Use SOCKS5 proxy created by Xray
// 	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
// 	return proxyclient.ProxySocks5(proxyURL, o)
// }

// DialSSR creates a custom transport that dials directly to the v2ray server
// instead of using a local SOCKS proxy.
func DialSSR(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	instance, _, err := StartSSR(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start ssr proxy: %w", err)
	}

	// Create a transport that uses our custom dialer
	tr := proxyclient.CreateTransport(o)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialContext(ctx, instance, network, addr)
	}
	tr.Proxy = nil

	return tr, nil
}
