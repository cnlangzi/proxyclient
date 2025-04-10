package ss

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cnlangzi/proxyclient"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/metadata"
)

func init() {
	proxyclient.RegisterProxy("ss", DialSS)
}

// ProxySS creates a RoundTripper for Shadowsocks proxy
func ProxySS(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// Start Shadowsocks instance
	port, err := StartSS(u, 0)
	if err != nil {
		return nil, err
	}

	// Get SOCKS5 proxy URL
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

	return proxyclient.ProxySocks5(proxyURL, o)
}

func DialSS(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {

	su, err := ParseSSURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Shadowsocks URL: %w", err)
	}
	cfg := su.Config

	m, err := createMethod(cfg.Method, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create Shadowsocks method: %w", err)
	}

	tr := proxyclient.CreateTransport(o)

	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {

		serverAddr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Shadowsocks server: %w", err)
		}

		ssConn, err := dialSsConn(m, conn, addr)

		if ssConn == nil {
			log.Printf("ss: panic on %s \n", su.Raw().String())
			return nil, fmt.Errorf("failed to create Shadowsocks connection: %w", err)
		}

		if err != nil {
			conn.Close()
			log.Printf("ss: panic on %s \n", su.Raw().String())
			return nil, fmt.Errorf("failed to create Shadowsocks connection: %w", err)
		}

		return ssConn, nil
	}

	tr.DisableCompression = true
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	tr.Proxy = nil

	return tr, nil
}

func dialSsConn(m shadowsocks.Method, c net.Conn, addr string) (conn net.Conn, err error) {
	defer recover() // nolint: errcheck

	destination := metadata.ParseSocksaddr(addr)
	conn, err = m.DialConn(c, destination)

	return
}
