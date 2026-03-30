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

func TestSetAndGet(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	// Inject a server directly into the map to avoid needing a real Instance.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Time{}}
	mu.Unlock()

	srv := getServer("socks5://127.0.0.1:1080")
	if srv == nil {
		t.Fatal("expected server, got nil")
	}
	mu.Lock()
	if servers["socks5://127.0.0.1:1080"].SocksPort != 1080 {
		t.Errorf("expected port 1080, got %d", srv.SocksPort)
	}
	mu.Unlock()
}

func TestGetNonExistent(t *testing.T) {
	ResetForTest()
	srv := getServer("socks5://127.0.0.1:9999")
	if srv != nil {
		t.Error("expected nil for non-existent server")
	}
}

func TestCloseRevivesServer(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	// Set up an active server.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Time{}}
	mu.Unlock()

	// Close it — marks DrainedAt non-zero.
	Close("socks5://127.0.0.1:1080")

	// Verify DrainedAt is non-zero (read through map under lock).
	mu.Lock()
	wasZero := servers["socks5://127.0.0.1:1080"].DrainedAt.IsZero()
	mu.Unlock()
	if wasZero {
		t.Error("expected DrainedAt to be non-zero after Close()")
	}

	// getServer should revive it (reset DrainedAt to zero).
	got := getServer("socks5://127.0.0.1:1080")
	if got == nil {
		t.Fatal("expected server after getServer")
	}

	// Verify DrainedAt is now zero — read through the map under lock.
	mu.Lock()
	stillZero := servers["socks5://127.0.0.1:1080"].DrainedAt.IsZero()
	mu.Unlock()
	if !stillZero {
		t.Error("expected DrainedAt to be reset to zero after getServer (revive)")
	}
}

func TestCloseIdempotent(t *testing.T) {
	ResetForTest()
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Time{}}
	mu.Unlock()

	Close("socks5://127.0.0.1:1080")
	Close("socks5://127.0.0.1:1080") // second call must not panic

	mu.Lock()
	defer mu.Unlock()
	if servers["socks5://127.0.0.1:1080"].DrainedAt.IsZero() {
		t.Error("expected DrainedAt non-zero")
	}
}

func TestCloseNonExistent(t *testing.T) {
	ResetForTest()
	// Must not panic.
	Close("socks5://127.0.0.1:9999")
}

func TestCloseAll(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Time{}}
	servers["socks5://127.0.0.1:1081"] = &Server{SocksPort: 1081, DrainedAt: time.Time{}}
	servers["socks5://127.0.0.1:1082"] = &Server{SocksPort: 1082, DrainedAt: time.Time{}}
	mu.Unlock()

	CloseAll()

	mu.Lock()
	defer mu.Unlock()
	for _, port := range []int{1080, 1081, 1082} {
		key := "socks5://127.0.0.1:" + itoa(port)
		if servers[key].DrainedAt.IsZero() {
			t.Errorf("expected server %s to be draining after CloseAll", key)
		}
	}
}

func TestSweeperRemovesExpired(t *testing.T) {
	ResetForTest()
	DrainTimeout = 80 * time.Millisecond
	SweepInterval = 15 * time.Millisecond

	// Inject an expired server directly into the map.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-200 * time.Millisecond)}
	mu.Unlock()

	// Call getServer to start the sweeper (it is lazy). This also revives
	// the server (resetting DrainedAt), so use a different URL.
	getServer("socks5://127.0.0.1:9998")

	// Inject another expired server after sweeper is running.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-200 * time.Millisecond)}
	mu.Unlock()

	// Wait enough for sweeper to run and remove the entry.
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	_, ok := servers["socks5://127.0.0.1:1080"]
	mu.Unlock()

	if ok {
		t.Error("expected server to be removed by sweeper after DrainTimeout")
	}
}

func TestSweeperSkipsRevivedEntry(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	// Entry is old enough to be collected, but we'll revive it before sweeper runs.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Now().Add(-100 * time.Millisecond)}
	mu.Unlock()

	// Revive via getServer before sweeper picks it up.
	getServer("socks5://127.0.0.1:1080")

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	srv, ok := servers["socks5://127.0.0.1:1080"]
	stillZero := srv != nil && srv.DrainedAt.IsZero()
	mu.Unlock()

	if !ok {
		t.Error("expected server to still exist after revive")
	}
	if !stillZero {
		t.Error("expected DrainedAt to be zero after revive")
	}
}

func TestSweeperSkipsActiveEntry(t *testing.T) {
	ResetForTest()
	DrainTimeout = 50 * time.Millisecond
	SweepInterval = 10 * time.Millisecond

	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Time{}}
	mu.Unlock()

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	_, ok := servers["socks5://127.0.0.1:1080"]
	mu.Unlock()

	if !ok {
		t.Error("expected active server to NOT be removed")
	}
}

func TestTryCloseAndDelete_NotInMap(t *testing.T) {
	ResetForTest()
	// Must not panic when url is not in map.
	tryCloseAndDelete("socks5://127.0.0.1:9999", nil)
}

func TestTryCloseAndDelete_WrongPointer(t *testing.T) {
	ResetForTest()
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: time.Now()}
	mu.Unlock()

	// Try to close with a different (non-existent) pointer.
	ghost := &Server{SocksPort: 9999, DrainedAt: time.Now()}
	tryCloseAndDelete("socks5://127.0.0.1:1080", ghost)

	mu.Lock()
	defer mu.Unlock()
	if _, ok := servers["socks5://127.0.0.1:1080"]; !ok {
		t.Error("expected server to remain when wrong pointer is passed")
	}
}

func TestTryCloseAndDelete_RevivedEntry(t *testing.T) {
	ResetForTest()
	now := time.Now()
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 1080, DrainedAt: now}
	mu.Unlock()

	// Manually revive the entry (simulate getServer racing with sweeper).
	mu.Lock()
	servers["socks5://127.0.0.1:1080"].DrainedAt = time.Time{}
	mu.Unlock()

	// tryCloseAndDelete should see DrainedAt==0 and skip.
	tryCloseAndDelete("socks5://127.0.0.1:1080", &Server{SocksPort: 1080, DrainedAt: now})

	mu.Lock()
	_, ok := servers["socks5://127.0.0.1:1080"]
	mu.Unlock()

	if !ok {
		t.Error("expected server to remain after tryCloseAndDelete on revived entry")
	}
}

func TestTryCloseAndDelete_ReplacedEntry(t *testing.T) {
	ResetForTest()
	old := &Server{SocksPort: 1080, DrainedAt: time.Now()}
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = old
	mu.Unlock()

	// Replace with a new server for same URL.
	mu.Lock()
	servers["socks5://127.0.0.1:1080"] = &Server{SocksPort: 9999, DrainedAt: time.Time{}}
	mu.Unlock()

	// tryCloseAndDelete with old pointer should not delete the new entry.
	tryCloseAndDelete("socks5://127.0.0.1:1080", old)

	mu.Lock()
	srv, ok := servers["socks5://127.0.0.1:1080"]
	mu.Unlock()

	if !ok {
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
			mu.Lock()
			servers[url] = &Server{SocksPort: 1000 + idx%10, DrainedAt: time.Time{}}
			mu.Unlock()
			_ = getServer(url)
			Close(url)
			_ = getServer(url)
		}(i)
	}
	wg.Wait()

	// No crash = pass. Verify map is consistent.
	mu.Lock()
	defer mu.Unlock()
	for url, srv := range servers {
		if url == "" || srv == nil {
			t.Errorf("nil entry in map: url=%q srv=%v", url, srv)
		}
	}
}
