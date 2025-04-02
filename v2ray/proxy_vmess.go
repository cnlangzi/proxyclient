package v2ray

import (
	"fmt"
	"net/http" // 标准库的 http
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("vmess", ProxyVmess)
}

func ProxyVmess(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	_, port, err := StartVmess(u.String(), 0)
	if err != nil {
		return nil, err
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

	return proxyclient.ProxySocks5(proxyURL, o)
}
