package v2ray

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("trojan", ProxyTrojan)
}

// ProxyTrojan creates a RoundTripper for Trojan proxy
func ProxyTrojan(u *url.URL, o *proxyclient.Options) http.RoundTripper {

	// Start Trojan instance
	_, port, err := StartTrojan(u.String(), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Trojan server: %v\n", err)
		return nil
	}

	// Get SOCKS5 proxy URL
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

	return proxyclient.ProxySocks5(proxyURL, o)
}
