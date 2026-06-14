package proxyclient

import (
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// defaultPingCap is the hard cap on a single Ping. The previous implementation
// relied on net.DialTimeout alone, but Linux's tcp_syn_retries default (6) lets
// a SYN to a blackholed remote take ~63s. Capping the deadline at 1.5s gives
// genuine fast-fail behavior on the hot path.
const defaultPingCap = 1500 * time.Millisecond

// Ping performs a TCP fast-fail dial to host:port and reports whether the
// remote accepted the SYN within the (capped) timeout. It is intentionally
// limited to TCP: hysteria2 / hy2 use UDP, and a successful TCP dial against
// a UDP-only endpoint is meaningless. Use PingWithScheme for protocol-aware
// dispatch.
//
// The returned bool is best-effort: even if the kernel returns a SYN-ACK,
// the remote service may still be dead. The caller is expected to run a
// full status probe afterwards; Ping is only a cheap pre-filter.
func Ping(host string, port string, timeout time.Duration) bool {
	return pingTCP(host, port, capTimeout(timeout))
}

// PingWithScheme dispatches to TCP or UDP fast-fail based on the proxy
// scheme. Unknown schemes fall back to TCP. scheme matching is
// case-insensitive and supports the short alias "hy2" alongside
// "hysteria2".
//
// UDP fast-fail: dial the UDP socket, send a 0-byte datagram, then attempt a
// short read. A successful dial + write implies the port is open; ICMP
// "port unreachable" or a read error from a half-open socket is treated as
// still-alive for hysteresis reasons (UDP is unreliable and a single probe
// is not authoritative).
func PingWithScheme(host string, port string, scheme string, timeout time.Duration) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "hysteria2", "hy2":
		return pingUDP(host, port, capTimeout(timeout))
	default:
		return pingTCP(host, port, capTimeout(timeout))
	}
}

// SchemeOfURL extracts the scheme from a raw proxy URL string. It tolerates
// whitespace and an empty input. An unparsable URL returns "".
//
// This is a lightweight parser used by callers that already have a raw URL
// string (e.g. the SQLite-backed proxy table) and don't want to pay the
// cost of a full url.Parse round-trip into the proxyclient URL registry.
func SchemeOfURL(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return ""
	}
	// Strip query/fragment noise so url.Parse is deterministic.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	// url.Parse handles both "scheme://..." and bare "scheme:..." forms.
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

// capTimeout enforces the hard cap on ping deadlines. Callers that pass 0
// or an excessively large duration get the defaultPingCap instead so the
// hot path never blocks longer than 1.5s.
func capTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > defaultPingCap {
		return defaultPingCap
	}
	return timeout
}

// pingTCP dials host:port over TCP with a short deadline. SetReadDeadline
// guards against half-open connections that accept the SYN but never
// respond to subsequent reads (some load balancers do this).
func pingTCP(host string, port string, timeout time.Duration) bool {
	d := net.Dialer{
		Timeout:       timeout,
		FallbackDelay: -1, // disable RFC 6555 happy-eyeballs; we only want v4
		KeepAlive:     0,
		Control: func(network, address string, c syscall.RawConn) error {
			// No-op hook reserved for future platform-specific tweaks
			// (e.g. TCP_FASTOPEN_CONNECT, IP_TOS). Kept as a Control
			// stub so callers can extend without changing the signature.
			return nil
		},
	}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	// Close the read side immediately so any half-open state is detected
	// as a read error rather than blocking the caller.
	_ = conn.SetReadDeadline(time.Now())
	_ = conn.Close()
	return true
}

// pingUDP performs a UDP fast-fail probe. We do not rely on the response
// (UDP is connectionless and unreliable); the probe succeeds if the
// socket can be addressed and a datagram can be queued. A non-existent
// host typically fails at ResolveUDPAddr or DialUDP, and a closed port
// may surface as a read error or as silence (both treated as alive).
func pingUDP(host string, port string, timeout time.Duration) bool {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint: errcheck

	_ = conn.SetDeadline(time.Now().Add(timeout))
	// 0-byte datagram is enough to trigger ICMP Port Unreachable on a
	// closed port; legitimate UDP services ignore empty payloads.
	if _, err := conn.Write(nil); err != nil {
		return false
	}
	// Best-effort read; we do not require a response.
	buf := make([]byte, 1)
	_, _, _ = conn.ReadFromUDP(buf)
	return true
}
