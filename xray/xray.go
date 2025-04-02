package xray

import (
	"fmt"
	"sync"

	core "github.com/xtls/xray-core/core"
)

var (
	mu      sync.Mutex
	proxies = make(map[string]*Server)
)

type Server struct {
	Instance  *core.Instance
	SocksPort int
}

func getServer(proxyURL string) *Server {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := proxies[proxyURL]; ok {
		return proxy
	}
	return nil
}

func setServer(proxyURL string, instance *core.Instance, port int) {
	mu.Lock()
	defer mu.Unlock()

	proxies[proxyURL] = &Server{
		Instance:  instance,
		SocksPort: port,
	}
}

func Close(proxyURL string) {
	mu.Lock()
	defer mu.Unlock()

	i, ok := proxies[proxyURL]
	if ok {
		i.Instance.Close()
		delete(proxies, proxyURL)
	}
}

func CloseAll() {
	mu.Lock()
	defer mu.Unlock()

	for url, server := range proxies {
		server.Instance.Close()
		delete(proxies, url)
	}
}

// 用 XHTTP 替代 WebSocket 的辅助函数
func useXHTTPInsteadOfWebSocket(ss *StreamSettings) {
	// 如果已配置 WebSocket
	if ss.Network == "ws" && ss.WSSettings != nil {
		// 保存 WebSocket 配置
		path := ss.WSSettings.Path
		host := ss.WSSettings.Host

		// 创建 XHTTP 配置
		ss.Network = "xhttp"
		ss.XHTTPSettings = &XHTTPSettings{
			Host:    host,
			Path:    path,
			Method:  "GET", // 默认方法
			Version: "h2",  // 默认使用 HTTP/2
		}

		// 清除 WebSocket 配置
		ss.WSSettings = nil

		fmt.Println("注意: WebSocket 传输已被自动转换为 XHTTP H2。这是 Xray 的推荐配置。")
	}
}
