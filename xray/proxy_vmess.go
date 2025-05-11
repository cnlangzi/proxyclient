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
	proxyclient.RegisterProxy("vmess", DialVmess)
}

// func ProxyVmess(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
// 	_, port, err := StartVmess(u, 0)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start vmess proxy: %w", err)
// 	}

// 	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
// 	return proxyclient.ProxySocks5(proxyURL, o)
// }

// DialVmess creates a custom transport that dials directly to the v2ray server
// instead of using a local SOCKS proxy.
func DialVmess(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	instance, _, err := StartVmess(u, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start vmess proxy: %w", err)
	}

	// Create a transport that uses our custom dialer
	tr := proxyclient.CreateTransport(o)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialContext(ctx, instance, network, addr)
	}
	tr.Proxy = nil

	return tr, nil
}
