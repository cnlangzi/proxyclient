package xray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// TrojanToXRay converts Trojan URL to Xray JSON configuration
func TrojanToXRay(u *url.URL, port int) ([]byte, int, error) {
	// Parse Trojan URL
	tu, err := ParseTrojanURL(u)
	if err != nil {
		return nil, 0, err
	}

	cfg := tu.Config

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
				"address":  cfg.Address,
				"port":     cfg.Port,
				"password": cfg.Password,
				"flow":     cfg.Flow,
				"level":    0,
			},
		},
	}

	// Create stream settings
	streamSettings := &StreamSettings{
		Network:  cfg.Type,
		Security: cfg.Security,
	}

	// Configure TLS
	if cfg.Security == "tls" {
		streamSettings.TLSSettings = &TLSSettings{
			ServerName:    cfg.SNI,
			AllowInsecure: cfg.AllowInsecure, // Use the value read from configuration
		}

		if cfg.Fingerprint != "" {
			streamSettings.TLSSettings.Fingerprint = cfg.Fingerprint
		}

		if cfg.ALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(cfg.ALPN, ",")
		}
	} else if cfg.Security == "xtls" {
		// Handle XTLS case
		streamSettings.Security = "xtls"
		streamSettings.XTLSSettings = &TLSSettings{
			ServerName:    cfg.SNI,
			AllowInsecure: cfg.AllowInsecure, // Use the value read from configuration
		}

		if cfg.Fingerprint != "" {
			streamSettings.XTLSSettings.Fingerprint = cfg.Fingerprint
		}

		if cfg.ALPN != "" {
			streamSettings.XTLSSettings.ALPN = strings.Split(cfg.ALPN, ",")
		}
	} else if cfg.Security == "reality" {
		// Handle Reality case
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &RealitySettings{
			ServerName:  cfg.SNI,
			Fingerprint: cfg.Fingerprint,
			// Reality doesn't need AllowInsecure setting
		}
	}

	// Configure based on transport type
	switch cfg.Type {
	case "ws":
		streamSettings.WSSettings = &WSSettings{
			Path: cfg.Path,
			Host: cfg.Host,
		}
	case "xhttp": // Explicitly specify to use XHTTP
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Host:    cfg.Host,
			Path:    cfg.Path,
			Method:  "GET",
			Version: "h2",
		}

		// Select HTTP version based on ALPN settings
		if cfg.ALPN != "" {
			if strings.Contains(cfg.ALPN, "h3") {
				streamSettings.XHTTPSettings.Version = "h3"
			}
		}
	case "tcp":
		if cfg.Host != "" || cfg.Path != "" {
			streamSettings.TCPSettings = &TCPSettings{
				Header: &Header{
					Type: "http",
					Request: map[string]interface{}{
						"path": []string{cfg.Path},
						"headers": map[string]interface{}{
							"Host": []string{cfg.Host},
						},
					},
				},
			}
		}
	case "grpc":
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: cfg.ServiceName,
			MultiMode:   false,
		}
	case "http":
		streamSettings.HTTPSettings = &HTTPSettings{
			Path: cfg.Path,
		}
		if cfg.Host != "" {
			streamSettings.HTTPSettings.Host = []string{cfg.Host}
		}
	}

	// Create complete configuration
	config := &XRayConfig{
		Log: &LogConfig{
			Loglevel: "error",
		},
		// Inbounds: []Inbound{
		// 	{
		// 		Tag:      "socks-in",
		// 		Port:     port,
		// 		Listen:   "127.0.0.1",
		// 		Protocol: "socks",
		// 		Settings: &SocksSetting{
		// 			Auth: "noauth",
		// 			UDP:  true,
		// 			IP:   "127.0.0.1",
		// 		},
		// 		Sniffing: &Sniffing{
		// 			Enabled:      true,
		// 			DestOverride: []string{"http", "tls"},
		// 		},
		// 	},
		// },
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
func StartTrojan(u *url.URL, port int) (*core.Instance, int, error) {

	trojanURL := u.String()

	// Check if already running
	server := getServer(trojanURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Convert to Xray JSON configuration
	jsonConfig, port, err := TrojanToXRay(u, port)
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
