package xray

import (
	"sync"
	"time"

	core "github.com/xtls/xray-core/core"
	// The following are necessary as they register handlers in their init functions.
	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	// Other optional features.
	_ "github.com/xtls/xray-core/app/dns"
	// _ "github.com/xtls/xray-core/app/dns/fakedns"
	_ "github.com/xtls/xray-core/app/log"
	// _ "github.com/xtls/xray-core/app/metrics"
	// _ "github.com/xtls/xray-core/app/policy"
	// _ "github.com/xtls/xray-core/app/reverse"
	_ "github.com/xtls/xray-core/app/router"
	// _ "github.com/xtls/xray-core/app/stats"
	// Fix dependency cycle caused by core import in internet package
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	// Developer preview features
	// _ "github.com/xtls/xray-core/app/observatory"
	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/loopback"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/proxy/wireguard"
	// Transports
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"
	_ "github.com/xtls/xray-core/transport/internet/headers/wireguard"
	// JSON & TOML & YAML
	_ "github.com/xtls/xray-core/main/json"
)

// drainTimeout is how long an instance stays in the servers map after Close() is called.
// This gives any in-flight operations a chance to finish before the instance is actually closed,
// which helps xray-core's goroutines clean up properly.
const drainTimeout = 30 * time.Second

// sweepInterval how often the background sweeper runs.
const sweepInterval = 10 * time.Second

type Server struct {
	Instance  *core.Instance
	SocksPort int
	DrainedAt time.Time // zero = active; non-zero = draining since this time
}

var (
	mu      sync.Mutex
	servers = make(map[string]*Server)
)

func init() {
	go sweeper()
}

func sweeper() {
	for {
		time.Sleep(sweepInterval)

		// Collect expired entries under lock, then release lock before closing
		// to avoid blocking all map operations while Instance.Close() runs.
		// Before each close and delete, re-acquire lock to re-verify the entry
		// is still the one being expired (not revived or replaced).
		var expired []struct {
			url  string
			srv  *Server
		}
		mu.Lock()
		now := time.Now()
		for url, srv := range servers {
			if !srv.DrainedAt.IsZero() && now.Sub(srv.DrainedAt) > drainTimeout {
				expired = append(expired, struct {
					url  string
					srv  *Server
				}{url, srv})
			}
		}
		mu.Unlock()

		// Close instances outside the critical section.
		for _, e := range expired {
			tryCloseAndDelete(e.url, e.srv)
		}
	}
}

func getServer(proxyURL string) *Server {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := servers[proxyURL]; ok {
		// If draining, revive it.
		if !proxy.DrainedAt.IsZero() {
			proxy.DrainedAt = time.Time{}
		}
		return proxy
	}
	return nil
}

func setServer(proxyURL string, instance *core.Instance, port int) {
	mu.Lock()
	defer mu.Unlock()

	servers[proxyURL] = &Server{
		Instance:   instance,
		SocksPort: port,
		DrainedAt:  time.Time{},
	}
}

// tryCloseAndDelete re-checks the entry under lock, closes it if still valid,
// then removes it from the map. The two-phase lock pattern ensures:
//   - The entry hasn't been revived (DrainedAt reset to zero) since collection.
//   - The entry hasn't been replaced by a newer server for the same URL.
func tryCloseAndDelete(url string, srv *Server) {
	mu.Lock()
	defer mu.Unlock()
	if servers[url] != srv || srv.DrainedAt.IsZero() {
		return
	}
	srv.Instance.Close() //nolint: errcheck
	if servers[url] == srv {
		delete(servers, url)
	}
}

// Close marks the server as draining. The sweeper goroutine will actually close
// the xray instance after drainTimeout elapses, giving in-flight operations a
// chance to finish cleanly and preventing premature close from leaking goroutines.
func Close(proxyURL string) {
	mu.Lock()
	defer mu.Unlock()

	i, ok := servers[proxyURL]
	if ok && i.DrainedAt.IsZero() {
		i.DrainedAt = time.Now()
	}
}

// CloseAll marks all servers as draining immediately. The sweeper will close
// each one after drainTimeout.
func CloseAll() {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	for _, srv := range servers {
		if srv.DrainedAt.IsZero() {
			srv.DrainedAt = now
		}
	}
}
