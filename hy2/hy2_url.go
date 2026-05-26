package hy2

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	proxyclient.RegisterParser("hysteria2", func(u *url.URL) (proxyclient.URL, error) {
		return ParseHY2URL(u)
	})
	proxyclient.RegisterParser("hy2", func(u *url.URL) (proxyclient.URL, error) {
		return ParseHY2URL(u)
	})
}

// HY2Config stores Hysteria2 URL parameters
type HY2Config struct {
	Auth              string
	Address           string
	Port              int
	SNI               string
	Insecure          bool
	ObfsType          string // "salamander" or "gecko"
	ObfsPassword      string
	ObfsMinPacketSize int
	ObfsMaxPacketSize int
	Up                string // e.g., "100 mbps"
	Down              string // e.g., "200 mbps"
	FastOpen          bool
	Remark            string

	raw *url.URL `json:"-"`
}

type HY2URL struct {
	Config *HY2Config
}

func (h *HY2URL) Raw() *url.URL {
	if h == nil {
		return nil
	}
	return h.Config.raw
}

func (h *HY2URL) Opaque() string {
	if h.Config == nil || h.Config.raw == nil {
		return ""
	}
	return strings.TrimPrefix(h.Config.raw.String(), h.Config.raw.Scheme+"://")
}

func (h *HY2URL) Host() string {
	if h.Config == nil {
		return ""
	}
	return h.Config.Address
}

func (h *HY2URL) Port() string {
	if h.Config == nil {
		return ""
	}
	return strconv.Itoa(h.Config.Port)
}

func (h *HY2URL) User() string {
	return ""
}

func (h *HY2URL) Password() string {
	if h.Config == nil {
		return ""
	}
	return h.Config.Auth
}

func (h *HY2URL) Protocol() string {
	if h.Config != nil && h.Config.raw != nil {
		return h.Config.raw.Scheme
	}
	return "hysteria2"
}

func (h *HY2URL) Name() string {
	if h.Config == nil {
		return ""
	}
	return h.Config.Remark
}

// ParseHY2URL parses hysteria2:// or hy2:// URL
func ParseHY2URL(u *url.URL) (*HY2URL, error) {
	// Extract auth (password)
	var auth string
	if u.User != nil {
		auth = u.User.Username()
		if p, ok := u.User.Password(); ok {
			auth = p
		}
	}

	// Extract host and port
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		// If no port specified, use default 443
		host = u.Host
		portStr = "443"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in HY2 URL: %w", err)
	}

	config := &HY2Config{
		Auth:    auth,
		Address: host,
		Port:    port,
		Remark:  u.Fragment,
		raw:     u,
	}

	// Parse query parameters
	query := u.Query()

	if v := query.Get("sni"); v != "" {
		config.SNI = v
	} else {
		config.SNI = host
	}

	if v := query.Get("insecure"); v != "" {
		config.Insecure = strings.ToLower(v) == "true" || v == "1"
	}

	// Obfuscation settings
	if v := query.Get("obfs"); v != "" {
		config.ObfsType = v
	}
	if v := query.Get("obfs-password"); v != "" {
		config.ObfsPassword = v
	}
	if v := query.Get("obfs-min-packet-size"); v != "" {
		if ps, err := strconv.Atoi(v); err == nil {
			config.ObfsMinPacketSize = ps
		}
	}
	if v := query.Get("obfs-max-packet-size"); v != "" {
		if ps, err := strconv.Atoi(v); err == nil {
			config.ObfsMaxPacketSize = ps
		}
	}

	// Bandwidth settings
	if v := query.Get("up"); v != "" {
		config.Up = v
	}
	if v := query.Get("down"); v != "" {
		config.Down = v
	}

	if v := query.Get("fastopen"); v != "" {
		config.FastOpen = strings.ToLower(v) == "true" || v == "1"
	}

	return &HY2URL{Config: config}, nil
}