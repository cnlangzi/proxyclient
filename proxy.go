package proxyclient

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type ProxyFunc func(*url.URL, *Options) (http.RoundTripper, error)

var (
	supportProxies = make(map[string]ProxyFunc)
)

func RegisterProxy(proto string, f ProxyFunc) {
	supportProxies[proto] = f
}

func CreateTransport(o *Options) *http.Transport {
	if o.Transport != nil {
		return o.Transport
	}

	tr := &http.Transport{
		DisableKeepAlives: false,
		MaxIdleConns:      5,
		IdleConnTimeout:   3 * time.Second,
	}

	if o.Timeout > 0 {
		tr.DialContext = (&net.Dialer{
			Timeout: o.Timeout / 2,
		}).DialContext

		tr.TLSHandshakeTimeout = o.Timeout / 2
		tr.ResponseHeaderTimeout = o.Timeout / 2
	}

	return tr
}

func SetDeadline(conn net.Conn, timeout time.Duration, disableKeepAlives bool) (net.Conn, error) {
	if timeout > 0 && disableKeepAlives {
		err := conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			// Ensure the connection is closed to avoid resource leaks
			conn.Close() // nolint: errcheck
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
	}
	return conn, nil
}

func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close() //nolint: errcheck

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func WithRecover(dial func() (net.Conn, error)) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			conn, err = nil, fmt.Errorf("net: dial panic: %v", r)
		}
	}()
	return dial()
}
