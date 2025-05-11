package xray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("trojan", DialTrojan)
}

// ProxyTrojan creates a RoundTripper for Trojan proxy
// func ProxyTrojan(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
// 	// Start Trojan client through Xray
// 	_, port, err := StartTrojan(u, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start Trojan proxy: %w", err)
// 	}

// 	// Use SOCKS5 proxy created by Xray
// 	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
// 	return proxyclient.ProxySocks5(proxyURL, o)
// }

// DialTrojan creates a custom transport that dials directly to the v2ray server
// instead of using a local SOCKS proxy.
func DialTrojan(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	instance, _, err := StartTrojan(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start trojan proxy: %w", err)
	}

	// Create a transport that uses our custom dialer
	tr := proxyclient.CreateTransport(o)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, instance, network, addr)
		if err != nil {
			return nil, err
		}

		return conn, conn.SetDeadline(time.Now().Add(o.Timeout))
	}
	tr.Proxy = nil

	return tr, nil
}
