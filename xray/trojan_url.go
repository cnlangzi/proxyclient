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
	// Register the SSR url parser
	proxyclient.RegisterParser("trojan", func(u *url.URL) (proxyclient.URL, error) {
		return ParseTrojanURL(u)
	})
}

// TrojanConfig stores Trojan URL parameters
type TrojanConfig struct {
	Password      string
	Address       string
	Port          int
	Flow          string
	Type          string
	Security      string
	Path          string
	Host          string
	SNI           string
	ALPN          string
	Fingerprint   string
	ServiceName   string
	AllowInsecure bool // Controls whether to allow insecure TLS connections

	raw *url.URL `json:"-"`
}

type TrojanURL struct {
	Config *TrojanConfig
}

func (v *TrojanURL) Raw() *url.URL {
	return v.Config.raw
}

func (v *TrojanURL) Opaque() string {
	return strings.TrimPrefix(v.Config.raw.String(), "trojan://")
}

func (v *TrojanURL) Host() string {
	return v.Config.Address
}

func (v *TrojanURL) Port() string {
	return strconv.Itoa(v.Config.Port)
}

func (v *TrojanURL) User() string {
	return ""
}

func (v *TrojanURL) Password() string {
	return v.Config.Password
}

func (v *TrojanURL) Protocol() string {
	return "trojan"
}

// ParseTrojanURL parses Trojan URL
// trojan://password@host:port?security=tls&type=tcp&sni=example.com...
func ParseTrojanURL(u *url.URL) (*TrojanURL, error) {

	// Extract user information
	if u.User == nil {
		return nil, fmt.Errorf("missing password in Trojan URL")
	}
	password := u.User.Username()

	// Extract host and port
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port in Trojan URL: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in Trojan URL: %w", err)
	}

	// Create configuration
	config := &TrojanConfig{
		Password:      password,
		Address:       host,
		Port:          port,
		Security:      "tls", // Trojan defaults to TLS
		Type:          "tcp", // Default transport type
		AllowInsecure: true,
	}

	// Parse query parameters
	query := u.Query()

	if v := query.Get("flow"); v != "" {
		config.Flow = v
	}

	if v := query.Get("type"); v != "" {
		config.Type = v
	}

	if v := query.Get("security"); v != "" {
		config.Security = v
	}

	if v := query.Get("path"); v != "" {
		config.Path = v
	}

	if v := query.Get("host"); v != "" {
		config.Host = v
	}

	if v := query.Get("sni"); v != "" {
		config.SNI = v
	} else if config.Host != "" {
		config.SNI = config.Host
	} else {
		config.SNI = host
	}

	if v := query.Get("alpn"); v != "" {
		config.ALPN = v
	}

	if v := query.Get("fp"); v != "" {
		config.Fingerprint = v
	}

	if v := query.Get("serviceName"); v != "" {
		config.ServiceName = v
	}

	if v := query.Get("allowInsecure"); v != "" {
		if strings.ToLower(v) == "false" || v == "0" {
			config.AllowInsecure = false
		}
	}

	config.raw = u

	return &TrojanURL{
		Config: config,
	}, nil
}
