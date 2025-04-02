package xray

import (
	"sync"

	core "github.com/xtls/xray-core/core"
)

var (
	mu      sync.Mutex
	servers = make(map[string]*Server)
)

type Server struct {
	Instance  *core.Instance
	SocksPort int
}

func getServer(proxyURL string) *Server {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := servers[proxyURL]; ok {
		return proxy
	}
	return nil
}

func setServer(proxyURL string, instance *core.Instance, port int) {
	mu.Lock()
	defer mu.Unlock()

	servers[proxyURL] = &Server{
		Instance:  instance,
		SocksPort: port,
	}
}

func Close(proxyURL string) {
	mu.Lock()
	defer mu.Unlock()

	i, ok := servers[proxyURL]
	if ok {
		i.Instance.Close()
		delete(servers, proxyURL)
	}
}

func CloseAll() {
	mu.Lock()
	defer mu.Unlock()

	for url, server := range servers {
		server.Instance.Close()
		delete(servers, url)
	}
}
