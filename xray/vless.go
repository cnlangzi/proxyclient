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
}

// ParseVless parses VLESS URL
// vless://uuid@host:port?encryption=none&type=tcp&security=tls&sni=example.com...
func ParseVless(vlessURL string) (*VlessConfig, error) {
	// Remove vless:// prefix
	vlessURL = strings.TrimPrefix(vlessURL, "vless://")

	// Parse as standard URL
	u, err := url.Parse("vless://" + vlessURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}

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
	config := &VlessConfig{
		UUID:          uuid,
		Address:       host,
		Port:          port,
		Encryption:    "none", // VLESS default encryption is none
		Type:          "tcp",  // Default transport type
		AllowInsecure: true,
	}

	// Parse query parameters
	query := u.Query()

	if v := query.Get("encryption"); v != "" {
		config.Encryption = v
	}

	if v := query.Get("flow"); v != "" {
		config.Flow = v
	}

	if v := query.Get("type"); v != "" {
		config.Type = v
		// XHTTP as explicitly supported type, but not auto-converted
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
	}

	if v := query.Get("alpn"); v != "" {
		config.ALPN = v
	}

	if v := query.Get("fp"); v != "" {
		config.Fingerprint = v
	}

	if v := query.Get("pbk"); v != "" {
		config.PublicKey = v
	}

	if v := query.Get("sid"); v != "" {
		config.ShortID = v
	}

	if v := query.Get("spx"); v != "" {
		config.SpiderX = v
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

// VlessToXRay converts VLESS URL to Xray JSON configuration
func VlessToXRay(vlessURL string, port int) ([]byte, int, error) {
	// Parse VLESS URL
	vless, err := ParseVless(vlessURL)
	if err != nil {
		return nil, 0, err
	}

	// Get a free port (if not provided)
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Create VLESS outbound configuration
	vlessSettings := map[string]interface{}{
		"vnext": []map[string]interface{}{
			{
				"address": vless.Address,
				"port":    vless.Port,
				"users": []map[string]interface{}{
					{
						"id":         vless.UUID,
						"flow":       vless.Flow,
						"encryption": vless.Encryption,
						"level":      0,
					},
				},
			},
		},
	}

	// Create stream settings
	streamSettings := &StreamSettings{
		Network:  vless.Type,
		Security: vless.Security,
	}

	// Configure TLS - update this section
	if vless.Security == "tls" {
		streamSettings.TLSSettings = &TLSSettings{
			ServerName:    vless.SNI,
			AllowInsecure: vless.AllowInsecure, // Use the value read from configuration
		}

		if vless.Fingerprint != "" {
			streamSettings.TLSSettings.Fingerprint = vless.Fingerprint
		}

		if vless.ALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(vless.ALPN, ",")
		}
	}

	// Configure XTLS - update this section
	if vless.Security == "xtls" {
		streamSettings.Security = "xtls"
		streamSettings.XTLSSettings = &TLSSettings{
			ServerName:    vless.SNI,
			AllowInsecure: vless.AllowInsecure, // Use the value read from configuration
		}

		if vless.Fingerprint != "" {
			streamSettings.XTLSSettings.Fingerprint = vless.Fingerprint
		}

		if vless.ALPN != "" {
			streamSettings.XTLSSettings.ALPN = strings.Split(vless.ALPN, ",")
		}
	}

	// Configure Reality
	if vless.Security == "reality" {
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &RealitySettings{
			ServerName:  vless.SNI,
			Fingerprint: vless.Fingerprint,
			PublicKey:   vless.PublicKey,
			ShortID:     vless.ShortID,
			SpiderX:     vless.SpiderX,
		}
	}

	// Configure based on transport type
	switch vless.Type {
	case "ws":
		streamSettings.WSSettings = &WSSettings{
			Path: vless.Path,
			Host: vless.Host, // Use independent Host field instead of headers
		}

	case "xhttp": // Add direct support for XHTTP
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Host:    vless.Host,
			Path:    vless.Path,
			Method:  "GET",
			Version: "h2",
		}

		// Select HTTP version based on ALPN settings
		if vless.ALPN != "" {
			if strings.Contains(vless.ALPN, "h3") {
				streamSettings.XHTTPSettings.Version = "h3"
			}
		}
	case "tcp":
		if vless.Host != "" || vless.Path != "" {
			streamSettings.TCPSettings = &TCPSettings{
				Header: &Header{
					Type: "http",
					Request: map[string]interface{}{
						"path": []string{vless.Path},
						"headers": map[string]interface{}{
							"Host": []string{vless.Host},
						},
					},
				},
			}
		}
	case "grpc":
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: vless.ServiceName,
			MultiMode:   false,
		}
	case "http":
		streamSettings.HTTPSettings = &HTTPSettings{
			Path: vless.Path,
		}
		if vless.Host != "" {
			streamSettings.HTTPSettings.Host = []string{vless.Host}
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
				Tag:            "vless-out",
				Protocol:       "vless",
				Settings:       vlessSettings,
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

// StartVless starts a VLESS client and returns Xray instance and local SOCKS port
func StartVless(vlessURL string, port int) (*core.Instance, int, error) {
	// Check if already running
	server := getServer(vlessURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Convert to Xray JSON configuration
	jsonConfig, port, err := VlessToXRay(vlessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// Start Xray instance
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// Register the running server
	setServer(vlessURL, instance, port)

	fmt.Printf("VLESS proxy started on socks5://127.0.0.1:%d\n", port)
	return instance, port, nil
}
