package proxyclient

import (
	"net"
	"testing"
	"time"
)

// TestPing_CapDeadline verifies the 1.5s hard cap on a blackholed remote.
// 198.51.100.0/24 is TEST-NET-2, guaranteed not to respond.
func TestPing_CapDeadline(t *testing.T) {
	start := time.Now()
	ok := Ping("198.51.100.1", "80", 30*time.Second)
	elapsed := time.Since(start)

	if ok {
		t.Fatalf("expected Ping to fail against TEST-NET-2")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Ping took %v, expected < 2s (1.5s cap)", elapsed)
	}
}

// TestPing_AcceptsLoopback verifies a live loopback listener returns true.
func TestPing_AcceptsLoopback(t *testing.T) {
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
	if elapsed > 500*time.Millisecond {
		t.Fatalf("loopback connect-refused took %v, expected < 500ms", elapsed)
	}
}

// TestPingWithScheme_TCPFallback verifies unknown scheme falls back to TCP.
func TestPingWithScheme_TCPFallback(t *testing.T) {
	start := time.Now()
	ok := PingWithScheme("198.51.100.1", "80", "vless", 30*time.Second)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("expected TCP fallback Ping to fail against TEST-NET-2")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("PingWithScheme (vless) took %v, expected < 2s", elapsed)
	}
}

// TestPingWithScheme_HysteriaUDP verifies hysteria2/hy2 routes to UDP path.
// UDP dial to TEST-NET-2 succeeds at syscall level (no SYN/ACK needed) so
// we expect true — this documents the "best-effort" semantics of pingUDP.
func TestPingWithScheme_HysteriaUDP(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2", "HYSTERIA2", "Hy2"} {
		start := time.Now()
		ok := PingWithScheme("198.51.100.1", "443", scheme, 200*time.Millisecond)
		elapsed := time.Since(start)
		if !ok {
			t.Fatalf("scheme=%q: expected UDP probe to return true (best-effort), got false in %v", scheme, elapsed)
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("scheme=%q: UDP probe took %v, expected < 500ms", scheme, elapsed)
		}
	}
}

// TestPingWithScheme_UDPUnresolvable verifies that an unresolvable host fails fast.
func TestPingWithScheme_UDPUnresolvable(t *testing.T) {
	start := time.Now()
	ok := PingWithScheme("invalid..host..name", "443", "hysteria2", 200*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatalf("expected UDP probe to fail for unresolvable host")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("UDP probe took %v for unresolvable host, expected < 500ms", elapsed)
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
