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

	return &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
	}
}

func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

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
