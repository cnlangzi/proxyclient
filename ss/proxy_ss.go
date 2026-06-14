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
	"github.com/sagernet/sing/common/metadata"
)

func init() {
	proxyclient.RegisterProxy("ss", DialSS)
}

// // ProxySS creates a RoundTripper for Shadowsocks proxy
// func ProxySS(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
// 	// Start Shadowsocks instance
// 	port, err := StartSS(u, 0)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Get SOCKS5 proxy URL
// 	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

// 	return proxyclient.ProxySocks5(proxyURL, o)
// }

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

		destination := metadata.ParseSocksaddr(addr)

		// Always close the underlying TCP socket on any failure path
		// (including panic) so a panic in m.DialConn cannot leak the fd
		// and starve the caller's worker pool. See panic-recovery notes
		// in proxyclient.WithRecover.
		closeConn := func() {
			if conn != nil {
				conn.Close() // nolint: errcheck
			}
		}

		ssConn, err := proxyclient.WithRecover(func() (net.Conn, error) {
			c, err := m.DialConn(conn, destination)
			if err != nil {
				return nil, err
			}

			return proxyclient.SetDeadline(c, o.Timeout, tr.DisableKeepAlives)
		})

		if ssConn == nil {
			// panic recovered by WithRecover
			closeConn()
			return nil, fmt.Errorf("ss: dial panic on %s", su.Raw().String())
		}

		if err != nil {
			closeConn()
			return nil, fmt.Errorf("failed to create Shadowsocks connection: %w", err)
		}

		return ssConn, nil
	}

	tr.DisableCompression = true
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	tr.Proxy = nil

	return tr, nil
}
