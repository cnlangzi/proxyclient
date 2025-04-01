package v2ray

import (
	"fmt"
	"net/http" // 标准库的 http
	"net/url"
	"os"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("vmess", ProxyVmess)
}

func ProxyVmess(u *url.URL, o *proxyclient.Options) http.RoundTripper {
	_, port, err := StartVmess(u.String(), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start VMess server: %v\n", err)
		return nil
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

	return proxyclient.ProxySocks5(proxyURL, o)

}
