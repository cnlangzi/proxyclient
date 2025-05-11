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
	proxyclient.RegisterProxy("vless", DialVless)
}

// func ProxyVless(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
// 	_, port, err := StartVless(u, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start vless proxy: %w", err)
// 	}

// 	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
// 	return proxyclient.ProxySocks5(proxyURL, o)
// }

// DialVless creates a custom transport that dials directly to the v2ray server
// instead of using a local SOCKS proxy.
func DialVless(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	instance, _, err := StartVless(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start vless proxy: %w", err)
	}

	// Create a transport that uses our custom dialer
	tr := proxyclient.CreateTransport(o)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, instance, network, addr)
		if err != nil {
			return nil, err
		}

		return proxyclient.SetDeadline(conn, o.Timeout, tr.DisableKeepAlives)
	}
	tr.Proxy = nil

	return tr, nil
}
