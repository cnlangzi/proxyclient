package xray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
)

// convertSSRMethod converts SSR encryption method to Xray supported method
func convertSSRMethod(method string) (string, error) {
	// Encryption methods supported by Xray
	methodMap := map[string]string{
		"aes-128-cfb":             "aes-128-cfb",
		"aes-256-cfb":             "aes-256-cfb",
		"chacha20":                "chacha20",
		"chacha20-ietf":           "chacha20-ietf",
		"aes-128-gcm":             "aes-128-gcm",
		"aes-256-gcm":             "aes-256-gcm",
		"chacha20-poly1305":       "chacha20-poly1305",
		"chacha20-ietf-poly1305":  "chacha20-ietf-poly1305",
		"xchacha20-poly1305":      "xchacha20-poly1305",
		"xchacha20-ietf-poly1305": "xchacha20-ietf-poly1305",
	}

	if v2Method, ok := methodMap[strings.ToLower(method)]; ok {
		fmt.Printf("Using Xray encryption method: %s\n", v2Method)
		return v2Method, nil
	}

	return "", fmt.Errorf("unsupported encryption method: %s", method)
}

// isBasicSSR checks if the SSR configuration can be handled by Xray
func isBasicSSR(config *SSRConfig) bool {
	// Check supported protocols
	protocol := strings.ToLower(config.Protocol)
	if protocol != "origin" &&
		protocol != "auth_aes128_md5" &&
		protocol != "auth_aes128_sha1" &&
		protocol != "auth_chain_a" {
		fmt.Printf("Unsupported SSR protocol: %s\n", protocol)
		return false
	}

	// Check supported obfuscations
	obfs := strings.ToLower(config.Obfs)
	if obfs != "plain" &&
		obfs != "http_simple" &&
		obfs != "tls1.2_ticket_auth" &&
		obfs != "http_post" {
		fmt.Printf("Unsupported SSR obfuscation: %s\n", obfs)
		return false
	}

	// Check supported encryption methods
	_, err := convertSSRMethod(config.Method)
	if err != nil {
		fmt.Printf("Unsupported SSR encryption method: %s\n", config.Method)
		return false
	}

	return true
}

// SSRToXRay converts SSR URL to Xray JSON configuration
func SSRToXRay(u *url.URL, port int) ([]byte, int, error) {
	// Parse SSR URL
	su, err := ParseSSRURL(u)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse SSR URL: %w", err)
	}

	cfg := su.Config

	// Check if configuration is supported
	if !isBasicSSR(cfg) {
		return nil, 0, fmt.Errorf("unsupported SSR configuration (protocol: %s, obfs: %s, method: %s)",
			cfg.Protocol, cfg.Obfs, cfg.Method)
	}

	// Get a free port (if not provided)
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Convert SSR method to Xray method
	xrayMethod, err := convertSSRMethod(cfg.Method)
	if err != nil {
		return nil, 0, err
	}

	// Create password with protocol/obfuscation configuration
	effectivePassword := cfg.Password

	// Handle protocol
	if strings.ToLower(cfg.Protocol) != "origin" {
		effectivePassword = fmt.Sprintf("%s:%s", cfg.Protocol, effectivePassword)
		if cfg.ProtocolParam != "" {
			effectivePassword = fmt.Sprintf("%s?protocolparam=%s", effectivePassword, cfg.ProtocolParam)
		}
	}

	// Handle obfuscation
	if strings.ToLower(cfg.Obfs) != "plain" {
		effectivePassword = fmt.Sprintf("%s:%s", cfg.Obfs, effectivePassword)
		if cfg.ObfsParam != "" {
			effectivePassword = fmt.Sprintf("%s?obfsparam=%s", effectivePassword, cfg.ObfsParam)
		}
	}

	// Shadowsocks outbound settings
	ssSettings := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"address":  cfg.Server,
				"port":     cfg.Port,
				"method":   xrayMethod,
				"password": effectivePassword,
				"uot":      true,
				"level":    0,
			},
		},
	}

	// Create configuration based on Xray JSON format
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
				Tag:      "shadowsocks-out",
				Protocol: "shadowsocks",
				Settings: ssSettings,
				Mux: &Mux{
					Enabled:     false,
					Concurrency: 8,
				},
			},
			{
				Tag:      "direct",
				Protocol: "freedom",
			},
		},
		// Routing: &RoutingConfig{
		// 	DomainStrategy: "AsIs",
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

// StartSSR starts SSR client and returns Xray instance and local SOCKS port
func StartSSR(u *url.URL, port int) (*core.Instance, int, error) {
	ssrURL := u.String()
	// Check if already running
	server := getServer(ssrURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Convert to Xray JSON configuration
	jsonConfig, port, err := SSRToXRay(u, port)
	if err != nil {
		return nil, 0, err
	}

	// Start Xray instance
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// Register the running server
	setServer(ssrURL, instance, port)

	fmt.Printf("SSR proxy started on socks5://127.0.0.1:%d\n", port)
	return instance, port, nil
}
