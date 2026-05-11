package xray

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := m.Run()
	ResetForTest()
	os.Exit(code)
}

// itoa avoids importing strconv just for int-to-string in tests.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}

// injectServer inserts a server directly into the sharded map for test injection.
func injectServer(url string, srv *Server) {
	idx := hashShard(url)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()
	if shardedServers[idx] == nil {
		shardedServers[idx] = make(map[string]*Server)
	}
	shardedServers[idx][url] = srv
}

// getFromShard reads a server from the sharded map (for test assertions).
func getFromShard(url string) *Server {
	idx := hashShard(url)
	shardedMu[idx].RLock()
	defer shardedMu[idx].RUnlock()
	return shardedServers[idx][url]
}

// reviveServer resets DrainedAt so the server is considered active again,
// used in tests to simulate a server coming back to life.
func reviveServer(url string) {
	idx := hashShard(url)
	shardedMu[idx].Lock()
	defer shardedMu[idx].Unlock()
	if shardedServers[idx] == nil {
		return
	}
	if srv, ok := shardedServers[idx][url]; ok {
		srv.DrainedAt = time.Time{}
	}
}

// existsInShard checks if a URL exists in the sharded map.
func existsInShard(url string) bool {
	return getFromShard(url) != nil
}

// countAllServers returns total number of servers across all shards.
func countAllServers() int {
	n := 0
	for idx := range shardedServers {
		shardedMu[idx].RLock()
		n += len(shardedServers[idx])
		shardedMu[idx].RUnlock()
	}
	return n
}

func TestSetAndGet(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Time{}})

	srv := getServer("socks5://127.0.0.1:1080")
	if srv == nil {
		t.Fatal("expected server, got nil")
	}
	if srv.SocksPort != 1080 {
		t.Errorf("expected port 1080, got %d", srv.SocksPort)
	}
}

func TestGetNonExistent(t *testing.T) {
	ResetForTest()
	srv := getServer("socks5://127.0.0.1:9999")
	if srv != nil {
		t.Error("expected nil for non-existent server")
	}
}

func TestCloseRemovesServer(t *testing.T) {
	ResetForTest()

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Time{}})

	Close("socks5://127.0.0.1:1080")

	if existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to be removed from map after Close()")
	}

	got := getServer("socks5://127.0.0.1:1080")
	if got != nil {
		t.Fatal("expected nil after getServer on removed server")
	}
}

func TestCloseIdempotent(t *testing.T) {
	ResetForTest()
	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Time{}})

	Close("socks5://127.0.0.1:1080")
	Close("socks5://127.0.0.1:1080") // second call must not panic

	if existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to be removed from map")
	}
}

func TestCloseNonExistent(t *testing.T) {
	ResetForTest()
	Close("socks5://127.0.0.1:9999")
}

func TestCloseAll(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Time{}})
	injectServer("socks5://127.0.0.1:1081", &Server{SocksPort: 1081, DrainedAt: time.Time{}})
	injectServer("socks5://127.0.0.1:1082", &Server{SocksPort: 1082, DrainedAt: time.Time{}})

	CloseAll()

	for _, port := range []int{1080, 1081, 1082} {
		key := "socks5://127.0.0.1:" + itoa(port)
		srv := getFromShard(key)
		if srv == nil || srv.DrainedAt.IsZero() {
			t.Errorf("expected server %s to be draining after CloseAll", key)
		}
	}
}

func TestSweeperRemovesExpired(t *testing.T) {
	ResetForTest()
	DrainTimeout = 80 * time.Millisecond
	SweepInterval = 15 * time.Millisecond

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-200 * time.Millisecond)})

	getServer("socks5://127.0.0.1:9998")

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-200 * time.Millisecond)})

	time.Sleep(300 * time.Millisecond)

	if existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to be removed by sweeper after DrainTimeout")
	}
}

func TestSweeperSkipsRevivedEntry(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	// Server is already draining when inserted.
	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-100 * time.Millisecond)})

	// getServer on a draining server returns nil and does NOT revive it.
	result := getServer("socks5://127.0.0.1:1080")
	if result != nil {
		t.Error("expected getServer to return nil for draining server")
	}

	// Wait for sweeper to run and close the draining entry.
	time.Sleep(200 * time.Millisecond)

	// Server should be gone — sweeper closed it because it was still draining.
	if existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to be removed by sweeper after DrainTimeout")
	}
}

func TestSweeperSkipsActiveEntry(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Time{}})

	time.Sleep(200 * time.Millisecond)

	if !existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected active server to NOT be removed")
	}
}

func TestTryCloseAndDelete_NotInMap(t *testing.T) {
	ResetForTest()
	tryCloseAndDelete("socks5://127.0.0.1:9999", nil)
}

func TestTryCloseAndDelete_WrongPointer(t *testing.T) {
	ResetForTest()
	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: time.Now()})

	ghost := &Server{SocksPort: 9999, DrainedAt: time.Now()}
	tryCloseAndDelete("socks5://127.0.0.1:1080", ghost)

	if !existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to remain when wrong pointer is passed")
	}
}

func TestTryCloseAndDelete_RevivedEntry(t *testing.T) {
	ResetForTest()
	now := time.Now()
	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: now})

	reviveServer("socks5://127.0.0.1:1080")

	tryCloseAndDelete("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: now})

	if !existsInShard("socks5://127.0.0.1:1080") {
		t.Error("expected server to remain after tryCloseAndDelete on revived entry")
	}
}

func TestTryCloseAndDelete_ReplacedEntry(t *testing.T) {
	ResetForTest()
	old := &Server{SocksPort: 1080, DrainedAt: time.Now()}
	injectServer("socks5://127.0.0.1:1080", old)

	injectServer("socks5://127.0.0.1:1080", &Server{SocksPort: 9999, DrainedAt: time.Time{}})

	tryCloseAndDelete("socks5://127.0.0.1:1080", old)

	srv := getFromShard("socks5://127.0.0.1:1080")
	if srv == nil {
		t.Fatal("expected server to still exist")
	}
	if srv.SocksPort != 9999 {
		t.Errorf("expected new server port 9999, got %d", srv.SocksPort)
	}
}

func TestConcurrentGetSetClose(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			url := "socks5://127.0.0.1:" + itoa(1000+idx%10)
			injectServer(url, &Server{SocksPort: 1000+idx%10, DrainedAt: time.Time{}})
			_ = getServer(url)
			Close(url)
			_ = getServer(url)
		}(i)
	}
	wg.Wait()

	if n := countAllServers(); n > 0 {
		t.Errorf("expected no servers after concurrent get/set/close, found %d", n)
	}
}
