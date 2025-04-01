package v2ray

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("vless", ProxyVless)
}

// ProxyVless creates a RoundTripper for VLESS proxy
func ProxyVless(u *url.URL, o *proxyclient.Options) http.RoundTripper {
	// Launch VLESS instance and get the SOCKS port
	_, port, err := StartVless(u.String(), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start VLESS server: %v\n", err)
		return nil
	}

	// Create a SOCKS5 proxy URL from the local port
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

	// Reuse the existing SOCKS5 proxy implementation
	return proxyclient.ProxySocks5(proxyURL, o)
}
