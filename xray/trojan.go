package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

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
}

// ParseTrojan parses Trojan URL
// trojan://password@host:port?security=tls&type=tcp&sni=example.com...
func ParseTrojan(trojanURL string) (*TrojanConfig, error) {
	// Remove trojan:// prefix
	trojanURL = strings.TrimPrefix(trojanURL, "trojan://")

	// Parse as standard URL
	u, err := url.Parse("trojan://" + trojanURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Trojan URL: %w", err)
	}

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

	return config, nil
}

// TrojanToXRay converts Trojan URL to Xray JSON configuration
func TrojanToXRay(trojanURL string, port int) ([]byte, int, error) {
	// Parse Trojan URL
	trojan, err := ParseTrojan(trojanURL)
	if err != nil {
		return nil, 0, err
	}

	// Get a free port if none provided
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Create Trojan outbound configuration
	trojanSettings := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"address":  trojan.Address,
				"port":     trojan.Port,
				"password": trojan.Password,
				"flow":     trojan.Flow,
				"level":    0,
			},
		},
	}

	// Create stream settings
	streamSettings := &StreamSettings{
		Network:  trojan.Type,
		Security: trojan.Security,
	}

	// Configure TLS
	if trojan.Security == "tls" {
		streamSettings.TLSSettings = &TLSSettings{
			ServerName:    trojan.SNI,
			AllowInsecure: trojan.AllowInsecure, // Use the value read from configuration
		}

		if trojan.Fingerprint != "" {
			streamSettings.TLSSettings.Fingerprint = trojan.Fingerprint
		}

		if trojan.ALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(trojan.ALPN, ",")
		}
	} else if trojan.Security == "xtls" {
		// Handle XTLS case
		streamSettings.Security = "xtls"
		streamSettings.XTLSSettings = &TLSSettings{
			ServerName:    trojan.SNI,
			AllowInsecure: trojan.AllowInsecure, // Use the value read from configuration
		}

		if trojan.Fingerprint != "" {
			streamSettings.XTLSSettings.Fingerprint = trojan.Fingerprint
		}

		if trojan.ALPN != "" {
			streamSettings.XTLSSettings.ALPN = strings.Split(trojan.ALPN, ",")
		}
	} else if trojan.Security == "reality" {
		// Handle Reality case
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &RealitySettings{
			ServerName:  trojan.SNI,
			Fingerprint: trojan.Fingerprint,
			// Reality doesn't need AllowInsecure setting
		}
	}

	// Configure based on transport type
	switch trojan.Type {
	case "ws":
		streamSettings.WSSettings = &WSSettings{
			Path: trojan.Path,
			Host: trojan.Host,
		}
	case "xhttp": // Explicitly specify to use XHTTP
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Host:    trojan.Host,
			Path:    trojan.Path,
			Method:  "GET",
			Version: "h2",
		}

		// Select HTTP version based on ALPN settings
		if trojan.ALPN != "" {
			if strings.Contains(trojan.ALPN, "h3") {
				streamSettings.XHTTPSettings.Version = "h3"
			}
		}
	case "tcp":
		if trojan.Host != "" || trojan.Path != "" {
			streamSettings.TCPSettings = &TCPSettings{
				Header: &Header{
					Type: "http",
					Request: map[string]interface{}{
						"path": []string{trojan.Path},
						"headers": map[string]interface{}{
							"Host": []string{trojan.Host},
						},
					},
				},
			}
		}
	case "grpc":
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: trojan.ServiceName,
			MultiMode:   false,
		}
	case "http":
		streamSettings.HTTPSettings = &HTTPSettings{
			Path: trojan.Path,
		}
		if trojan.Host != "" {
			streamSettings.HTTPSettings.Host = []string{trojan.Host}
		}
	}

	// Create complete configuration
	config := &XRayConfig{
		Log: &LogConfig{
			Loglevel: "warning",
		},
		Inbounds: []Inbound{
			{
				Tag:      "socks-in",
				Port:     port,
				Listen:   "127.0.0.1",
				Protocol: "socks",
				Settings: &SocksSetting{
					Auth: "noauth",
					UDP:  true,
					IP:   "127.0.0.1",
				},
				Sniffing: &Sniffing{
					Enabled:      true,
					DestOverride: []string{"http", "tls"},
				},
			},
		},
		Outbounds: []Outbound{
			{
				Tag:            "trojan-out",
				Protocol:       "trojan",
				Settings:       trojanSettings,
				StreamSettings: streamSettings,
				Mux: &Mux{
					Enabled:     false,
					Concurrency: runtime.NumCPU(),
				},
			},
			{
				Tag:      "direct",
				Protocol: "freedom",
			},
		},
		// Routing: &RoutingConfig{
		// 	Rules: []RoutingRule{
		// 		{
		// 			Type:        "field",
		// 			OutboundTag: "direct",
		// 			IP:          []string{"geoip:private"},
		// 		},
		// 	},
		// },
	}

	// Convert to JSON
	buf, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	return buf, port, nil
}

// StartTrojan starts a Trojan client and returns Xray instance and local SOCKS port
func StartTrojan(trojanURL string, port int) (*core.Instance, int, error) {
	// Check if already running
	server := getServer(trojanURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Convert to Xray JSON configuration
	jsonConfig, port, err := TrojanToXRay(trojanURL, port)
	if err != nil {
		return nil, 0, err
	}

	// Start Xray instance
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// Register the running server
	setServer(trojanURL, instance, port)

	return instance, port, nil
}
