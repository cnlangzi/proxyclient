package xray

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	// Register the VLESS url parser
	proxyclient.RegisterParser("vless", func(u *url.URL) (proxyclient.URL, error) {
		return ParseVlessURL(u)
	})
}

// VlessConfig stores VLESS URL parameters
type VlessConfig struct {
	UUID          string
	Address       string
	Port          int
	Encryption    string
	Flow          string
	Type          string
	Security      string
	Path          string
	Host          string
	SNI           string
	ALPN          string
	Fingerprint   string
	PublicKey     string
	ShortID       string
	SpiderX       string
	ServiceName   string
	AllowInsecure bool // Controls whether to allow insecure TLS connections
	Remark        string

	raw *url.URL `json:"-"`
}

type VlessURL struct {
	Config *VlessConfig
}

func (v *VlessURL) Raw() *url.URL {
	return v.Config.raw
}

func (v *VlessURL) Opaque() string {
	return strings.TrimPrefix(v.Config.raw.String(), "vless://")
}

func (v *VlessURL) Host() string {
	return v.Config.Address
}

func (v *VlessURL) Port() string {
	return strconv.Itoa(v.Config.Port)
}

func (v *VlessURL) User() string {
	return v.Config.UUID
}

func (v *VlessURL) Password() string {
	return ""
}

func (v *VlessURL) Protocol() string {
	return "vless"
}

func (v *VlessURL) Name() string {
	return v.Config.Remark
}

// ParseVlessURL parses VLESS URL
// vless://uuid@host:port?encryption=none&type=tcp&security=tls&sni=example.com...
func ParseVlessURL(u *url.URL) (*VlessURL, error) {
	// Extract user information
	if u.User == nil {
		return nil, fmt.Errorf("missing user info in VLESS URL")
	}
	uuid := u.User.Username()

	// Extract host and port
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port in VLESS URL: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in VLESS URL: %w", err)
	}

	// Create configuration
	cfg := &VlessConfig{
		UUID:          uuid,
		Address:       host,
		Port:          port,
		Encryption:    "none", // VLESS default encryption is none
		Type:          "tcp",  // Default transport type
		AllowInsecure: true,
		raw:           u,
		Remark:        u.Fragment,
	}

	// Parse query parameters
	query := u.Query()

	if v := query.Get("encryption"); v != "" {
		cfg.Encryption = v
	}

	if v := query.Get("flow"); v != "" {
		cfg.Flow = v
	}

	if v := query.Get("type"); v != "" {
		cfg.Type = v
		// XHTTP as explicitly supported type, but not auto-converted
	}

	if v := query.Get("security"); v != "" {
		cfg.Security = v
	}

	if v := query.Get("path"); v != "" {
		cfg.Path = v
	}

	if v := query.Get("host"); v != "" {
		cfg.Host = v
	}

	if v := query.Get("sni"); v != "" {
		cfg.SNI = v
	} else if cfg.Host != "" {
		cfg.SNI = cfg.Host
	}

	if v := query.Get("alpn"); v != "" {
		cfg.ALPN = v
	}

	if v := query.Get("fp"); v != "" {
		cfg.Fingerprint = v
	}

	if v := query.Get("pbk"); v != "" {
		cfg.PublicKey = v
	}

	if v := query.Get("sid"); v != "" {
		cfg.ShortID = v
	}

	if v := query.Get("spx"); v != "" {
		cfg.SpiderX = v
	}

	if v := query.Get("serviceName"); v != "" {
		cfg.ServiceName = v
	}

	if v := query.Get("allowInsecure"); v != "" {
		if strings.ToLower(v) == "false" || v == "0" {
			cfg.AllowInsecure = false
		}
	}

	return &VlessURL{
		Config: cfg,
	}, nil
}
