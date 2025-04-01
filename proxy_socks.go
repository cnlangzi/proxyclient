package proxyclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
	"h12.io/socks"
)

func init() {
	supportProxies["socks5"] = ProxySocks5
	supportProxies["socks5h"] = ProxySocks5
	supportProxies["socks4"] = ProxySocks4
	supportProxies["socks4a"] = ProxySocks4

}

func ProxySocks5(u *url.URL, o *Options) http.RoundTripper {
	tr := CreateTransport(o)

	dialer := &net.Dialer{}

	if o.Timeout > 0 {
		dialer.Timeout = o.Timeout
	}

	var auth *proxy.Auth
	if u.User != nil {
		auth = new(proxy.Auth)
		auth.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	d, _ := proxy.SOCKS5("tcp", net.JoinHostPort(u.Hostname(), u.Port()), auth, dialer)

	xd := d.(proxy.ContextDialer)
	tr.DialContext = xd.DialContext
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := xd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}

		tlsConfig := tr.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}

		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = host

		tlsConn := tls.Client(conn, tlsConfig)

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}

	tr.Proxy = nil

	return tr
}

func ProxySocks4(u *url.URL, o *Options) http.RoundTripper {
	tr := CreateTransport(o)

	proxyURL := u.String()

	if o.Timeout > 0 {
		proxyURL += "?timeout=" + o.Timeout.String()
	}

	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks.Dial(proxyURL)(network, addr)
	}
	// tr.DialTLSContext = tr.DialContext

	return tr
}
