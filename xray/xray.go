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

// DrainTimeout is how long an instance stays in the servers map after Close()
// is called. This gives in-flight operations a chance to finish before the
// instance is actually closed, preventing goroutine leaks in xray-core.
var DrainTimeout = 30 * time.Second

// SweepInterval is how often the background sweeper runs.
var SweepInterval = 10 * time.Second

// ShardN is the number of shards for the servers map.
// A higher value reduces lock contention but uses more memory.
const ShardN = 256

type Server struct {
	Instance  *core.Instance
	SocksPort int
	DrainedAt time.Time // zero = active; non-zero = draining since this time
}

var (
	shardedMu      [ShardN]sync.RWMutex
	shardedServers [ShardN]map[string]*Server
	sweeperOnce    sync.Once
	stopCh         chan struct{}
	sweeperWG      sync.WaitGroup
)

func hashShard(proxyURL string) int {
	// Lightweight non-allocating FNV-1a style hash specialized for strings.
	var h uint32 = 2166136261
	for i := 0; i < len(proxyURL); i++ {
		h ^= uint32(proxyURL[i])
		h *= 16777619
	}
	return int(h % uint32(ShardN))
}

// StartSweeper launches the background sweeper goroutine if not already running.
// It is called automatically by the public API; you do not need to call it.
func startSweeper() {
	sweeperOnce.Do(func() {
		ch := make(chan struct{})
		stopCh = ch
		sweeperWG.Add(1)
		go func(stop <-chan struct{}) {
			sweeper(stop)
			sweeperWG.Done()
		}(ch) // pass as parameter so the goroutine uses its own copy
	})
}

// StopSweeper stops the running sweeper goroutine (if any) and waits for it
// to exit, then resets its Once gate so a new sweeper can be started.
// Intended for use in tests only.
func StopSweeper() {
	if stopCh != nil {
		close(stopCh)
	}
	sweeperWG.Wait()
	// Reset state so a fresh sweeper can be started in the next test.
	stopCh = nil
	sweeperOnce = sync.Once{}
}

func sweeper(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(SweepInterval):
		}

		expired := []struct {
			url string
			srv *Server
		}{}
		now := time.Now()
		for idx := range shardedServers {
			shardedMu[idx].RLock()
			for url, srv := range shardedServers[idx] {
				if !srv.DrainedAt.IsZero() && now.Sub(srv.DrainedAt) > DrainTimeout {
					expired = append(expired, struct {
						url string
						srv *Server
					}{url, srv})
				}
			}
			shardedMu[idx].RUnlock()
		}

		for _, e := range expired {
			tryCloseAndDelete(e.url, e.srv)
		}
	}
}

func getServer(proxyURL string) *Server {
	startSweeper()
	idx := hashShard(proxyURL)
	shardedMu[idx].RLock()
	defer shardedMu[idx].RUnlock()

	if shardedServers[idx] == nil {
		return nil
	}
	if proxy, ok := shardedServers[idx][proxyURL]; ok {
		// If server is draining, don't reuse it — return nil and let caller create fresh.
		// This prevents the "revive" bug where getServer() resets DrainedAt, blocking sweeper.
		if !proxy.DrainedAt.IsZero() {
			return nil
		}
		return proxy
	}
	return nil
}

func setServer(proxyURL string, instance *core.Instance, port int) {
	startSweeper()
	idx := hashShard(proxyURL)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()

	if shardedServers[idx] == nil {
		shardedServers[idx] = make(map[string]*Server)
	}
	shardedServers[idx][proxyURL] = &Server{
		Instance:  instance,
		SocksPort: port,
		DrainedAt: time.Time{},
	}
}

// tryCloseAndDelete checks the entry under lock, closes it if still draining,
// then removes it from the map. The lock pattern ensures:
//   - The entry hasn't been revived (DrainedAt reset to zero) since collection.
//   - The entry hasn't been replaced by a newer server for the same URL.
func tryCloseAndDelete(url string, srv *Server) {
	idx := hashShard(url)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()
	if srv == nil || shardedServers[idx][url] != srv || srv.DrainedAt.IsZero() {
		return
	}
	if srv.Instance != nil {
		srv.Instance.Close() //nolint: errcheck
	}
	if shardedServers[idx][url] == srv {
		delete(shardedServers[idx], url)
	}
}

// Close synchronously closes the xray instance and removes it from the servers
// map. This prevents goroutine and memory leaks when testing high volumes of
// proxies where the previous delayed-close behavior caused resource accumulation.
func Close(proxyURL string) {
	idx := hashShard(proxyURL)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()

	srv, ok := shardedServers[idx][proxyURL]
	if !ok {
		return
	}
	if srv.Instance != nil {
		srv.Instance.Close() //nolint: errcheck
	}
	delete(shardedServers[idx], proxyURL)
}

// CloseImmediately synchronously closes the xray instance and removes it from
// the servers map. Use this when you need immediate cleanup and are certain no
// other goroutines are using the instance.
func CloseImmediately(proxyURL string) {
	idx := hashShard(proxyURL)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()

	srv, ok := shardedServers[idx][proxyURL]
	if !ok {
		return
	}
	if srv.Instance != nil {
		srv.Instance.Close() //nolint: errcheck
	}
	delete(shardedServers[idx], proxyURL)
}

// CloseAll marks all servers as draining immediately. The sweeper will close
// each one after DrainTimeout.
func CloseAll() {
	startSweeper()
	now := time.Now()
	for idx := range shardedServers {
		shardedMu[idx].Lock()
		for _, srv := range shardedServers[idx] {
			if srv.DrainedAt.IsZero() {
				srv.DrainedAt = now
			}
		}
		shardedMu[idx].Unlock()
	}
}

// ResetForTest clears all entries from the servers map and resets the sweeper,
// so tests get a clean state without reassigning the map variable (which would
// race with any goroutines still iterating over the old map). Safe to call from tests.
func ResetForTest() {
	for idx := range shardedServers {
		shardedMu[idx].Lock()
		shardedServers[idx] = nil
		shardedMu[idx].Unlock()
	}
	StopSweeper()
}
