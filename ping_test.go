package proxyclient

import (
	"net"
	"os"
	"testing"
	"time"
)

// skipIfOffline returns true when the OFFLINE environment variable is set,
// allowing timing-sensitive / network-dependent tests to opt out in CI
// environments where they are flaky.
func skipIfOffline(t *testing.T) {
	if os.Getenv("OFFLINE") != "" {
		t.Skip("skipping network/timing-sensitive test in OFFLINE mode")
	}
}

// TestCapTimeout verifies the cap logic in isolation from the network.
func TestCapTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "zero timeout uses default cap",
			timeout: 0,
			want:    defaultPingCap,
		},
		{
			name:    "negative timeout uses default cap",
			timeout: -1 * time.Second,
			want:    defaultPingCap,
		},
		{
			name:    "timeout greater than cap is capped",
			timeout: defaultPingCap + 1*time.Second,
			want:    defaultPingCap,
		},
		{
			name:    "timeout just below cap is unchanged",
			timeout: defaultPingCap - 10*time.Millisecond,
			want:    defaultPingCap - 10*time.Millisecond,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := capTimeout(tt.timeout)
			if got != tt.want {
				t.Fatalf("capTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

// TestPing_CapDeadline verifies the 1.5s hard cap on a blackholed remote.
// 198.51.100.0/24 is TEST-NET-2, guaranteed not to respond.
//
// This is timing-sensitive and may be flaky in constrained CI
// environments, so it can be disabled by setting the OFFLINE env var.
func TestPing_CapDeadline(t *testing.T) {
	skipIfOffline(t)

	start := time.Now()
	ok := Ping("198.51.100.1", "80", 30*time.Second)
	elapsed := time.Since(start)

	if ok {
		t.Fatalf("expected Ping to fail against TEST-NET-2")
	}
	// Allow some slack above the 1.5s cap to reduce CI flakiness.
	if elapsed > 3*time.Second {
		t.Fatalf("Ping took %v, expected < 3s (1.5s cap + slack)", elapsed)
	}
}

// TestPing_AcceptsLoopback verifies a live loopback listener returns true.
func TestPing_AcceptsLoopback(t *testing.T) {
	skipIfOffline(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("can't bind loopback: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	if !Ping(host, port, 1500*time.Millisecond) {
		t.Fatalf("expected Ping to succeed against a live loopback listener")
	}
}

// TestPing_NonExistentPort verifies ECONNREFUSED returns false quickly.
func TestPing_NonExistentPort(t *testing.T) {
	skipIfOffline(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("can't bind loopback: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	_ = ln.Close()

	start := time.Now()
	ok := Ping("127.0.0.1", port, 1500*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("expected Ping to fail against an unbound port")
	}
	// 1s of slack above the natural < 100ms ECONNREFUSED round-trip
	// keeps the test useful even on slow CI runners.
	if elapsed > 1*time.Second {
		t.Fatalf("loopback connect-refused took %v, expected < 1s", elapsed)
	}
}

// TestPingWithScheme_TCPFallback verifies unknown scheme falls back to TCP.
func TestPingWithScheme_TCPFallback(t *testing.T) {
	skipIfOffline(t)

	start := time.Now()
	ok := PingWithScheme("198.51.100.1", "80", "vless", 30*time.Second)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("expected TCP fallback Ping to fail against TEST-NET-2")
	}
	// Same slack budget as TestPing_CapDeadline.
	if elapsed > 3*time.Second {
		t.Fatalf("PingWithScheme (vless) took %v, expected < 3s", elapsed)
	}
}

// TestPingWithScheme_HysteriaUDP verifies hysteria2/hy2 routes to UDP path.
// UDP dial to TEST-NET-2 succeeds at syscall level (no SYN/ACK needed) so
// we expect true — this documents the "best-effort" semantics of pingUDP.
func TestPingWithScheme_HysteriaUDP(t *testing.T) {
	skipIfOffline(t)

	for _, scheme := range []string{"hysteria2", "hy2", "HYSTERIA2", "Hy2"} {
		start := time.Now()
		ok := PingWithScheme("198.51.100.1", "443", scheme, 200*time.Millisecond)
		elapsed := time.Since(start)
		if !ok {
			t.Fatalf("scheme=%q: expected UDP probe to return true (best-effort), got false in %v", scheme, elapsed)
		}
		// UDP probe is local-syscall fast; 2s is generous slack.
		if elapsed > 2*time.Second {
			t.Fatalf("scheme=%q: UDP probe took %v, expected < 2s", scheme, elapsed)
		}
	}
}

// TestPingWithScheme_UDPUnresolvable verifies that an unresolvable host fails fast.
func TestPingWithScheme_UDPUnresolvable(t *testing.T) {
	skipIfOffline(t)

	start := time.Now()
	ok := PingWithScheme("invalid..host..name", "443", "hysteria2", 200*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("expected UDP probe to fail for unresolvable host")
	}
	// Resolver failures are local-only; 1s of slack is plenty.
	if elapsed > 1*time.Second {
		t.Fatalf("UDP probe took %v for unresolvable host, expected < 1s", elapsed)
	}
}

// TestSchemeOfURL verifies scheme extraction from various proxy URL shapes.
func TestSchemeOfURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ss://user:pass@host:8388", "ss"},
		{"vless://uuid@host:443?type=ws", "vless"},
		{"hysteria2://pw@host:443/?sni=x", "hysteria2"},
		{"hy2://pw@host:443", "hy2"},
		{"http://1.2.3.4:8080", "http"},
		{"  socks5://h:1080  ", "socks5"},
		{"", ""},
		{"SS://upper", "ss"},
	}
	for _, c := range cases {
		got := SchemeOfURL(c.in)
		if got != c.want {
			t.Errorf("SchemeOfURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
