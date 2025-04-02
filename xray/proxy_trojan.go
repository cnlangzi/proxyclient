package xray

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("trojan", ProxyTrojan)
}

// ProxyTrojan 创建 Trojan 代理的 RoundTripper
func ProxyTrojan(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// 通过 Xray 启动 Trojan 客户端
	_, port, err := StartTrojan(u.String(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start Trojan proxy: %w", err)
	}

	// 使用由 Xray 创建的 SOCKS5 代理
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return proxyclient.ProxySocks5(proxyURL, o)
}
