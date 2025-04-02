package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
)

// SSRConfig stores ShadowsocksR URL parameters
type SSRConfig struct {
	Server        string
	Port          int
	Method        string
	Password      string
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
	Name          string
}

// ParseSSR parses ShadowsocksR URL
// ssr://base64(server:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks)
func ParseSSR(ssrURL string) (*SSRConfig, error) {
	// Remove ssr:// prefix
	ssrURL = strings.TrimPrefix(ssrURL, "ssr://")

	// Decode base64
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(ssrURL)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(ssrURL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode SSR URL: %w", err)
		}
	}

	text := string(decoded)

	// Separate main part and parameter part
	var mainPart, paramPart string
	if idx := strings.Index(text, "/?"); idx >= 0 {
		mainPart = text[:idx]
		paramPart = text[idx+2:]
	} else if idx := strings.Index(text, "?"); idx >= 0 {
		mainPart = text[:idx]
		paramPart = text[idx+1:]
	} else {
		mainPart = text
	}

	// Parse main part
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid SSR URL format")
	}

	serverPort, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Decode password
	password, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[5])
	if err != nil {
		// Try standard base64
		password, err = base64.StdEncoding.DecodeString(parts[5])
		if err != nil {
			return nil, fmt.Errorf("failed to decode password: %w", err)
		}
	}

	config := &SSRConfig{
		Server:   parts[0],
		Port:     serverPort,
		Protocol: parts[2],
		Method:   parts[3],
		Obfs:     parts[4],
		Password: string(password),
	}

	// Parse parameter part
	if paramPart != "" {
		params := strings.Split(paramPart, "&")
		for _, param := range params {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}

			key := kv[0]
			value := kv[1]

			decodedValue, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(value)
			if err != nil {
				// Try standard base64
				decodedValue, err = base64.StdEncoding.DecodeString(value)
				if err != nil {
					// Use original value
					decodedValue = []byte(value)
				}
			}

			switch key {
			case "obfsparam":
				config.ObfsParam = string(decodedValue)
			case "protoparam":
				config.ProtocolParam = string(decodedValue)
			case "remarks":
				config.Name = string(decodedValue)
			}
		}
	}

	return config, nil
}

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
func SSRToXRay(ssrURL string, port int) ([]byte, int, error) {
	// Parse SSR URL
	ssr, err := ParseSSR(ssrURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse SSR URL: %w", err)
	}

	// Check if configuration is supported
	if !isBasicSSR(ssr) {
		return nil, 0, fmt.Errorf("unsupported SSR configuration (protocol: %s, obfs: %s, method: %s)",
			ssr.Protocol, ssr.Obfs, ssr.Method)
	}

	// Get a free port (if not provided)
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Convert SSR method to Xray method
	xrayMethod, err := convertSSRMethod(ssr.Method)
	if err != nil {
		return nil, 0, err
	}

	// Create password with protocol/obfuscation configuration
	effectivePassword := ssr.Password

	// Handle protocol
	if strings.ToLower(ssr.Protocol) != "origin" {
		effectivePassword = fmt.Sprintf("%s:%s", ssr.Protocol, effectivePassword)
		if ssr.ProtocolParam != "" {
			effectivePassword = fmt.Sprintf("%s?protocolparam=%s", effectivePassword, ssr.ProtocolParam)
		}
	}

	// Handle obfuscation
	if strings.ToLower(ssr.Obfs) != "plain" {
		effectivePassword = fmt.Sprintf("%s:%s", ssr.Obfs, effectivePassword)
		if ssr.ObfsParam != "" {
			effectivePassword = fmt.Sprintf("%s?obfsparam=%s", effectivePassword, ssr.ObfsParam)
		}
	}

	// Shadowsocks outbound settings
	ssSettings := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"address":  ssr.Server,
				"port":     ssr.Port,
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
func StartSSR(ssrURL string, port int) (*core.Instance, int, error) {
	// Check if already running
	server := getServer(ssrURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Convert to Xray JSON configuration
	jsonConfig, port, err := SSRToXRay(ssrURL, port)
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
