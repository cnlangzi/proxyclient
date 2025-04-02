package v2ray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"
)

// VlessConfig holds the parsed VLESS URL parameters
type VlessConfig struct {
	ID         string // User ID
	Address    string // Server address
	Port       int    // Server port
	Network    string // Network type (tcp, ws, etc.)
	Security   string // Security type (tls, none)
	Path       string // Path for websocket/http/grpc
	Host       string // Host header value
	SNI        string // TLS SNI
	Type       string // Header type
	Flow       string // Flow control (xtls-rprx-direct, etc.)
	Encryption string // Encryption method (usually "none" for VLESS)
	Remark     string // Remarks
}

// VlessOutboundSetting represents VLESS outbound configuration
type VlessOutboundSetting struct {
	Vnext []VlessNext `json:"vnext"`
}

// VlessNext represents VLESS server configuration
type VlessNext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VlessUser `json:"users"`
}

// VlessUser represents VLESS user configuration
type VlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
	Level      int    `json:"level,omitempty"`
}

// VlessToV2Ray converts a VLESS URL to V2Ray JSON configuration
func VlessToV2Ray(vlessURL string, port int) ([]byte, int, error) {
	// Parse VLESS URL
	vless, err := parseVlessURL(vlessURL)
	if err != nil {
		return nil, 0, err
	}

	// Get a free port if not specified
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Generate a complete v2ray configuration by reusing the existing structure
	config := createCompleteVlessConfig(vless, port)

	// Return JSON format (reuse the same marshaling logic)
	buf, err := json.MarshalIndent(config, "", "  ")
	return buf, port, err
}

// parseVlessURL parses a VLESS URL into a VLESSConfig struct
func parseVlessURL(vlessURL string) (*VlessConfig, error) {
	// Strip the vless:// prefix
	vlessURL = strings.TrimPrefix(vlessURL, "vless://")

	// Parse URL (format: [uuid]@[address]:[port]?[params]#[remark])
	u, err := url.Parse("vless://" + vlessURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}

	// Extract user ID from user info
	var id string
	if u.User != nil {
		id = u.User.Username()
	}

	// Extract host and port
	host := u.Hostname()
	portStr := u.Port()

	if host == "" {
		return nil, fmt.Errorf("missing host in VLESS URL")
	}

	// Parse port
	var port int
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in VLESS URL: %w", err)
		}
	} else {
		// Default port
		port = 443
	}

	// Parse query parameters
	params := u.Query()

	vless := &VlessConfig{
		ID:         id,
		Address:    host,
		Port:       port,
		Network:    params.Get("type"),       // tcp, ws, etc.
		Security:   params.Get("security"),   // tls, none
		Path:       params.Get("path"),       // for ws/http/grpc
		Host:       params.Get("host"),       // for http/ws host header
		SNI:        params.Get("sni"),        // for TLS server name
		Type:       params.Get("headerType"), // header type
		Flow:       params.Get("flow"),       // flow control
		Encryption: params.Get("encryption"), // usually "none" for VLESS
		Remark:     u.Fragment,               // the comment/remark
	}

	// Default values
	if vless.Network == "" {
		vless.Network = "tcp"
	}
	if vless.Encryption == "" {
		vless.Encryption = "none"
	}

	return vless, nil
}

// createCompleteVlessConfig creates a complete V2Ray configuration for VLESS
func createCompleteVlessConfig(vless *VlessConfig, port int) *V2RayConfig {
	// Reuse the same configuration structure as VMess
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
				Tag:      "vless-out",
				Protocol: "vless",
				Settings: &VlessOutboundSetting{
					Vnext: []VlessNext{
						{
							Address: vless.Address,
							Port:    vless.Port,
							Users: []VlessUser{
								{
									ID:         vless.ID,
									Encryption: vless.Encryption,
									Flow:       vless.Flow,
									Level:      0,
								},
							},
						},
					},
				},
				// Reuse the stream settings builder with our VLESS config
				StreamSettings: buildVlessStreamSettings(vless),
				Mux: &Mux{
					Enabled:     true,
					Concurrency: runtime.NumCPU(),
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

// buildVlessStreamSettings builds stream settings for VLESS
// This is very similar to buildEnhancedStreamSettings but adapted for VLESS
func buildVlessStreamSettings(vless *VlessConfig) *StreamSettings {
	ss := &StreamSettings{
		Network:  vless.Network,
		Security: "none",
	}

	// Configure transport based on network type - reuse same logic as VMess
	switch strings.ToLower(vless.Network) {
	case "ws":
		ss.WSSettings = &WSSettings{
			Path: vless.Path,
		}
		if vless.Host != "" {
			ss.WSSettings.Headers = map[string]string{
				"Host": vless.Host,
			}
		}
	case "tcp":
		if vless.Type == "http" {
			ss.TCPSettings = &TCPSettings{
				Header: &Header{
					Type: "http",
					Request: &HeaderItem{
						Version: "1.1",
						Method:  "GET",
						Path:    []string{vless.Path},
						Headers: map[string][]string{},
					},
				},
			}
			if vless.Host != "" {
				ss.TCPSettings.Header.Request.Headers["Host"] = []string{vless.Host}
			}
		}
	case "kcp":
		ss.KCPSettings = &KCPSettings{
			MTU:              1350,
			TTI:              20,
			UplinkCapacity:   5,
			DownlinkCapacity: 20,
			Congestion:       false,
			ReadBufferSize:   1,
			WriteBufferSize:  1,
		}
		if vless.Type != "" {
			ss.KCPSettings.Header = &Header{
				Type: vless.Type,
			}
		}
	case "http":
		ss.HTTPSettings = &HTTPSettings{
			Path: vless.Path,
		}
		if vless.Host != "" {
			ss.HTTPSettings.Host = []string{vless.Host}
		}
	case "quic":
		ss.QUICSettings = &QUICSettings{
			Security: "none",
		}
		if vless.Type != "" {
			ss.QUICSettings.Header = &Header{
				Type: vless.Type,
			}
		}
	case "grpc":
		ss.GRPCSettings = &GRPCSettings{
			ServiceName: vless.Path,
			MultiMode:   false,
		}
	}

	// Configure TLS if needed
	if strings.ToLower(vless.Security) == "tls" {
		ss.Security = "tls"
		ss.TLSSettings = &tlscfg.TLSConfig{
			ServerName: vless.SNI,
			Insecure:   true,
		}
		// If ALPN is needed, add it here
	}

	return ss
}

// StartVless loads the config and starts a V2Ray instance
func StartVless(vlessURL string, port int) (*core.Instance, int, error) {
	// Check if we already have a server for this VLESS URL
	inst := getServer(vlessURL)
	if inst != nil {
		return inst.Instance, inst.SocksPort, nil
	}

	// Get JSON configuration
	jsonConfig, port, err := VlessToV2Ray(vlessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// Create server config directly using the core.StartInstance function
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start V2Ray instance: %w", err)
	}

	// Store the instance and port for future reuse
	setServer(vlessURL, instance, port)

	return instance, port, nil
}
