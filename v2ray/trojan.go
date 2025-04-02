package v2ray

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"
)

// TrojanConfig stores parsed Trojan URL parameters
type TrojanConfig struct {
	Password string // Authentication password
	Address  string // Server address
	Port     int    // Server port
	SNI      string // TLS SNI value
	Type     string // Transport type (tcp, ws, etc.)
	Path     string // WebSocket path
	Host     string // Host header value
	Flow     string // Flow control settings
	Remark   string // Remark information
}

// TrojanOutboundSetting represents Trojan outbound configuration
type TrojanOutboundSetting struct {
	Servers []TrojanServerObject `json:"servers"`
}

// TrojanServerObject represents Trojan server configuration
type TrojanServerObject struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	Level    int    `json:"level,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

// TrojanToV2Ray converts Trojan URL to V2Ray JSON configuration
func TrojanToV2Ray(trojanURL string, port int) ([]byte, int, error) {
	// Parse Trojan URL
	trojan, err := parseTrojanURL(trojanURL)
	if err != nil {
		return nil, 0, err
	}

	// If port not specified, get an available port
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Generate complete v2ray configuration
	config := createCompleteTrojanConfig(trojan, port)

	// Return in JSON format
	buf, err := json.MarshalIndent(config, "", "  ")
	return buf, port, err
}

// parseTrojanURL parses Trojan URL into TrojanConfig struct
func parseTrojanURL(trojanURL string) (*TrojanConfig, error) {
	// Remove trojan:// prefix
	trojanURL = strings.TrimPrefix(trojanURL, "trojan://")

	// Parse URL
	u, err := url.Parse("trojan://" + trojanURL)
	if err != nil {
		return nil, fmt.Errorf("Invalid Trojan URL: %w", err)
	}

	// Extract password
	var password string
	if u.User != nil {
		password = u.User.Username()
	}

	// Extract host and port
	host := u.Hostname()
	portStr := u.Port()

	if host == "" {
		return nil, fmt.Errorf("Missing host in Trojan URL")
	}

	// Parse port
	var port int
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("Invalid port in Trojan URL: %w", err)
		}
	} else {
		// Default port
		port = 443
	}

	// Parse query parameters
	params := u.Query()

	trojan := &TrojanConfig{
		Password: password,
		Address:  host,
		Port:     port,
		SNI:      params.Get("sni"),  // TLS SNI
		Type:     params.Get("type"), // Transport type
		Path:     params.Get("path"), // WebSocket path
		Host:     params.Get("host"), // WebSocket Host
		Flow:     params.Get("flow"), // Flow control
		Remark:   u.Fragment,         // Remark
	}

	// Set default SNI (if not provided)
	if trojan.SNI == "" {
		trojan.SNI = host
	}

	// Default type is tcp
	if trojan.Type == "" {
		trojan.Type = "tcp"
	}

	return trojan, nil
}

// createCompleteTrojanConfig creates complete V2Ray configuration for Trojan
func createCompleteTrojanConfig(trojan *TrojanConfig, port int) *V2RayConfig {
	// Reuse the same configuration structure as VMess/VLESS
	config := &V2RayConfig{
		Log: &LogConfig{
			Access:   "",
			Error:    "",
			Loglevel: "info",
		},
		DNS:     &DNSConfig{},
		Routing: &RoutingConfig{},
		Inbounds: []Inbound{
			{
				Tag:      "socks-in",
				Port:     port,
				Listen:   "127.0.0.1",
				Protocol: "socks",
				Settings: &SocksSetting{
					Auth:      "noauth",
					UDP:       true,
					IP:        "127.0.0.1",
					UserLevel: 0,
				},
				Sniffing: &Sniffing{
					Enabled:      true,
					DestOverride: []string{"http", "tls"},
				},
			},
		},
		Outbounds: []Outbound{
			{
				Tag:      "trojan-out",
				Protocol: "trojan",
				Settings: &TrojanOutboundSetting{
					Servers: []TrojanServerObject{
						{
							Address:  trojan.Address,
							Port:     trojan.Port,
							Password: trojan.Password,
							Flow:     trojan.Flow,
							Level:    0,
						},
					},
				},
				// Build stream settings for Trojan
				StreamSettings: buildTrojanStreamSettings(trojan),
				Mux: &Mux{
					Enabled:     false,
					Concurrency: 8,
					Protocol:    "auto",
				},
			},
			{
				Tag:      "direct",
				Protocol: "freedom",
				Settings: map[string]interface{}{
					"domainStrategy": "UseIP",
					"userLevel":      0,
				},
			},
			{
				Tag:      "block",
				Protocol: "blackhole",
				Settings: map[string]interface{}{},
			},
		},
		Policy: &PolicyConfig{
			Levels: map[string]Level{
				"0": {
					HandshakeTimeout:  4,
					ConnIdle:          300,
					UplinkOnly:        1,
					DownlinkOnly:      1,
					BufferSize:        10240,
					StatsUserUplink:   true,
					StatsUserDownlink: true,
				},
			},
			System: &SystemPolicy{
				StatsInboundUplink:    true,
				StatsInboundDownlink:  true,
				StatsOutboundUplink:   true,
				StatsOutboundDownlink: true,
			},
		},
		Stats: &StatsConfig{},
	}

	return config
}

// buildTrojanStreamSettings builds stream settings for Trojan
func buildTrojanStreamSettings(trojan *TrojanConfig) *StreamSettings {
	ss := &StreamSettings{
		Network:  trojan.Type,
		Security: "tls", // Trojan uses TLS by default
	}

	// Configure transport based on network type
	switch strings.ToLower(trojan.Type) {
	case "ws":
		ss.WSSettings = &WSSettings{
			Path: trojan.Path,
		}
		if trojan.Host != "" {
			ss.WSSettings.Headers = map[string]string{
				"Host": trojan.Host,
			}
		}
	case "tcp":
		// Most Trojan servers use plain TCP
		ss.TCPSettings = &TCPSettings{}
	case "grpc":
		ss.GRPCSettings = &GRPCSettings{
			ServiceName: trojan.Path,
			MultiMode:   false,
		}
	}

	// Configure TLS settings
	ss.TLSSettings = &tlscfg.TLSConfig{
		ServerName:        trojan.SNI,
		Insecure:          true,  // Allow insecure connections
		DisableSystemRoot: false, // Use system root certificates
		// ALPN:              cfgcommon.NewStringList([]string{"h2", "http/1.1"}),
	}

	return ss
}

// StartTrojan loads configuration and starts V2Ray instance
func StartTrojan(trojanURL string, port int) (*core.Instance, int, error) {
	// Check if there's already a server for this Trojan URL
	inst := getServer(trojanURL)
	if inst != nil {
		return inst.Instance, inst.SocksPort, nil
	}

	// Get JSON configuration
	jsonConfig, port, err := TrojanToV2Ray(trojanURL, port)
	if err != nil {
		log.Printf("Failed to convert Trojan URL: %v", err)
		return nil, 0, err
	}

	// Use core.StartInstance function to directly create server configuration
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to start V2Ray instance: %w", err)
	}

	// Store instance and port for future reuse
	setServer(trojanURL, instance, port)

	return instance, port, nil
}
