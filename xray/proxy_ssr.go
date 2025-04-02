package xray

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("ssr", ProxySSR)
}

// ProxySSR 创建 SSR 代理的 RoundTripper
func ProxySSR(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// 通过 Xray 启动 SSR 客户端
	_, port, err := StartSSR(u.String(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to start SSR proxy: %w", err)
	}

	// 使用由 Xray 创建的 SOCKS5 代理
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return proxyclient.ProxySocks5(proxyURL, o)
}
