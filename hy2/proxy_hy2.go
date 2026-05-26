package hy2

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterProxy("hysteria2", DialHY2)
	proxyclient.RegisterProxy("hy2", DialHY2)
}

// obfsConnFactory implements client.ConnFactory interface.
// It wraps raw UDP connections with Salamander or Gecko obfuscation.
// The addr parameter is not used since we bind to a wildcard address
// and the actual destination is determined by the QUIC transport.
type obfsConnFactory struct {
	ObfsType          string // "salamander" or "gecko"
	ObfsPassword      string
	ObfsMinPacketSize int
	ObfsMaxPacketSize int
}

// New creates a new obfuscated UDP connection
func (f *obfsConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	// Create raw UDP conn - each call gets a fresh connection
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	// Ensure conn is closed if obfuscation setup fails
	var obfuscated net.PacketConn
	switch f.ObfsType {
	case "salamander":
		obfuscated, err = obfs.WrapPacketConnSalamander(conn, []byte(f.ObfsPassword))
		if err != nil {
			conn.Close() //nolint: errcheck
			return nil, err
		}
	case "gecko":
		obfuscated, err = obfs.WrapPacketConnGecko(conn, obfs.GeckoOptions{
			Password:      []byte(f.ObfsPassword),
			MinPacketSize: f.ObfsMinPacketSize,
			MaxPacketSize: f.ObfsMaxPacketSize,
		})
		if err != nil {
			conn.Close() //nolint: errcheck
			return nil, err
		}
	default:
		return conn, nil
	}
	return obfuscated, nil
}

// DialHY2 creates a RoundTripper for Hysteria2 proxy
func DialHY2(u *url.URL, o *proxyclient.Options) (http.RoundTripper, error) {
	// Parse HY2 URL
	hy2URL, err := ParseHY2URL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HY2 URL: %w", err)
	}
	cfg := hy2URL.Config

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Build hysteria client config
	hyConfig := &client.Config{
		ServerAddr: serverAddr,
		Auth:       cfg.Auth,
		TLSConfig: client.TLSConfig{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: cfg.Insecure,
		},
		FastOpen: cfg.FastOpen,
	}

	// Parse bandwidth
	if cfg.Up != "" || cfg.Down != "" {
		hyConfig.BandwidthConfig, err = parseBandwidth(cfg.Up, cfg.Down)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bandwidth: %w", err)
		}
	}

	// Apply obfuscation if configured
	if cfg.ObfsType != "" && cfg.ObfsPassword != "" {
		hyConfig.ConnFactory = &obfsConnFactory{
			ObfsType:          cfg.ObfsType,
			ObfsPassword:      cfg.ObfsPassword,
			ObfsMinPacketSize: cfg.ObfsMinPacketSize,
			ObfsMaxPacketSize: cfg.ObfsMaxPacketSize,
		}
	}

	// Create HY2 client
	hy2Client, _, err := client.NewClient(hyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HY2 client: %w", err)
	}

	// Create transport with custom dial
	tr := proxyclient.CreateTransport(o)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return hy2Client.TCP(addr)
	}
	tr.Proxy = nil

	return tr, nil
}

// parseBandwidth converts bandwidth strings to client.BandwidthConfig
func parseBandwidth(upStr, downStr string) (client.BandwidthConfig, error) {
	cfg := client.BandwidthConfig{}

	if upStr != "" {
		tx, err := parseBandwidthValue(upStr)
		if err != nil {
			return cfg, fmt.Errorf("invalid up bandwidth: %w", err)
		}
		cfg.MaxTx = tx
	}

	if downStr != "" {
		rx, err := parseBandwidthValue(downStr)
		if err != nil {
			return cfg, fmt.Errorf("invalid down bandwidth: %w", err)
		}
		cfg.MaxRx = rx
	}

	return cfg, nil
}

// parseBandwidthValue parses bandwidth string like "100 mbps" or "50 Mbps" to bytes/sec
func parseBandwidthValue(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	// Split into number and unit
	var numStr, unit string
	foundDigit := false
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' || s[i] == '.' {
			numStr += string(s[i])
			foundDigit = true
		} else if foundDigit {
			unit = strings.TrimSpace(s[i:])
			break
		}
	}

	if numStr == "" {
		return 0, fmt.Errorf("no number found in bandwidth value")
	}

	var multiplier uint64
	switch {
	case unit == "" || strings.HasPrefix(unit, "bps"):
		multiplier = 1
	case strings.HasPrefix(unit, "kbps"):
		multiplier = 1_000
	case strings.HasPrefix(unit, "mbps"):
		multiplier = 1_000_000
	case strings.HasPrefix(unit, "gbps"):
		multiplier = 1_000_000_000
	default:
		return 0, fmt.Errorf("unsupported bandwidth unit: %q", unit)
	}

	var val float64
	if _, err := fmt.Sscanf(numStr, "%f", &val); err != nil {
		return 0, fmt.Errorf("failed to parse bandwidth number: %w", err)
	}

	return uint64(val * float64(multiplier)), nil
}