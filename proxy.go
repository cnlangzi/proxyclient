package proxyclient

import (
	"net"
	"net/http"
	"net/url"
)

type ProxyFunc func(*url.URL, *Options) (http.RoundTripper, error)

var (
	supportProxies = make(map[string]ProxyFunc)
)

func RegisterProxy(proto string, f ProxyFunc) {
	supportProxies[proto] = f
}

func CreateTransport(o *Options) *http.Transport {
	return o.Transport.Clone()
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
