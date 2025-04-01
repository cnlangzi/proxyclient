package v2ray

import (
	"sync"

	core "github.com/v2fly/v2ray-core/v5"
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
	}
}
