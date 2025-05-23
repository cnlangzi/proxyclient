package proxyclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
	"h12.io/socks"
)

func init() {
	supportProxies["socks5"] = ProxySocks4
	supportProxies["socks5h"] = ProxySocks5
	supportProxies["socks4"] = ProxySocks4
	supportProxies["socks4a"] = ProxySocks4

}

func ProxySocks5(u *url.URL, o *Options) (http.RoundTripper, error) {
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

	d, err := proxy.SOCKS5("tcp", net.JoinHostPort(u.Hostname(), u.Port()), auth, dialer)
	if err != nil {
		return nil, err
	}

	xd := d.(proxy.ContextDialer)
	tr.DialContext = xd.DialContext
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialTLSContext(ctx, xd.DialContext, network, addr, tr.TLSClientConfig)
	}

	tr.Proxy = nil

	return tr, nil
}

func ProxySocks4(u *url.URL, o *Options) (http.RoundTripper, error) {
	tr := CreateTransport(o)

	proxyURL := u.String()

	if o.Timeout > 0 {
		proxyURL += "?timeout=" + o.Timeout.String()
	}

	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks.Dial(proxyURL)(network, addr)
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialTLSContext(ctx, tr.DialContext, network, addr, tr.TLSClientConfig)
		if err != nil {
			return nil, err
		}

		err = conn.SetDeadline(time.Now().Add(o.Timeout))
		if err != nil {
			conn.Close() // Ensure the connection is closed to avoid resource leaks
			return nil, err
		}
		return conn, nil
	}

	tr.Proxy = nil

	return tr, nil
}

type Dialer func(ctx context.Context, network string, address string) (net.Conn, error)

func dialTLSContext(ctx context.Context, dialer Dialer, network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	conn, err := dialer(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
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
