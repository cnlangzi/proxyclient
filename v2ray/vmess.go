package v2ray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"
	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
)

// Enhanced VmessConfig to support more features
type VmessConfig struct {
	Add      string              `json:"add"`
	Port     proxyclient.JsonInt `json:"port"`
	ID       string              `json:"id"`
	Aid      proxyclient.JsonInt `json:"aid"`
	Net      string              `json:"net"`
	Type     string              `json:"type"` // Transport header type for tcp/kcp
	Path     string              `json:"path"` // HTTP/WebSocket path
	Host     string              `json:"host"` // HTTP host
	TLS      string              `json:"tls"`
	SNI      string              `json:"sni"`
	Alpn     string              `json:"alpn"`
	V        string              `json:"v"`        // Version
	PS       string              `json:"ps"`       // Remarks
	Security string              `json:"security"` // Encryption method
}

// VmessToV2Ray converts a VMess URL to V2Ray JSON configuration
func VmessToV2Ray(vmessURL string, port int) ([]byte, int, error) {
	// Strip the vmess:// prefix
	encoded := strings.TrimPrefix(vmessURL, "vmess://")

	// Decode from Base64
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Unmarshal to VMessConfig
	var vmess VmessConfig
	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return nil, 0, fmt.Errorf("JSON parsing failed: %w", err)
	}

	if port < 1 {
		port, err = proxyclient.GetFreePort()

		if err != nil {
			return nil, 0, err
		}
	}

	// Generate a complete v2ray configuration
	config := createCompleteConfig(&vmess, port)

	// Return JSON format
	buf, err := json.MarshalIndent(config, "", "  ")
	return buf, port, err
}

func base64Decode(encoded string) ([]byte, error) {
	// Support different encoding methods
	if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func createCompleteConfig(vmess *VmessConfig, port int) *V2RayConfig {
	// Create a more complete configuration
	config := &V2RayConfig{
		Log: &LogConfig{
			Access:   "",
			Error:    "",
			Loglevel: "info",
		},
		DNS: &DNSConfig{
			// Servers: []interface{}{
			// 	"114.114.114.114",
			// 	"8.8.4.4",
			// 	"1.1.1.1",
			// 	"localhost",
			// },
		},
		Routing: &RoutingConfig{
			// DomainStrategy: "AsIs",
			// Rules: []RoutingRule{
			// {
			// 	Type:        "field",
			// 	Domain:      []string{"geosite:category-ads"},
			// 	OutboundTag: "block",
			// },
			// 	{
			// 		Type:        "field",
			// 		IP:          []string{"127.0.0.1"},
			// 		OutboundTag: "direct",
			// 	},
			// },
		},
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
			// {
			// 	Tag:      "http-in",
			// 	Port:     port,
			// 	Listen:   "127.0.0.1",
			// 	Protocol: "http",
			// 	Settings: &HttpSetting{
			// 		AllowTransparent: true,
			// 		UserLevel:        0,
			// 	},
			// 	Sniffing: &Sniffing{
			// 		Enabled:      true,
			// 		DestOverride: []string{"http", "tls"},
			// 	},
			// },
		},
		Outbounds: []Outbound{
			{
				Tag:      "vmess-out",
				Protocol: "vmess",
				Settings: &VMessOutboundSetting{
					Vnext: []VNext{
						{
							Address: vmess.Add,
							Port:    vmess.Port.Value(),
							Users: []User{
								{
									ID:       vmess.ID,
									AlterID:  vmess.Aid.Value(),
									Security: getSecurityMethod(vmess),
									Level:    0,
								},
							},
						},
					},
				},
				StreamSettings: buildEnhancedStreamSettings(vmess),
				Mux: &Mux{
					Enabled:     true,
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

func getSecurityMethod(vmess *VmessConfig) string {
	if vmess.Security != "" {
		return vmess.Security
	}
	return "auto"
}

func buildEnhancedStreamSettings(vmess *VmessConfig) *StreamSettings {
	ss := &StreamSettings{
		Network:  vmess.Net,
		Security: "none",
	}

	// Configure transport based on network type
	switch strings.ToLower(vmess.Net) {
	case "ws":
		configureWS(ss, vmess)
	case "tcp":
		configureTCP(vmess, ss)
	case "kcp":
		configureKCP(ss, vmess)
	case "http":
		configureHTTP(ss, vmess)
	case "quic":
		configureQUIC(ss, vmess)
	case "grpc":
		configureGRPC(ss, vmess)
	}

	// Configure TLS if needed
	if strings.ToLower(vmess.TLS) == "tls" {
		ss.Security = "tls"
		ss.TLSSettings = &tlscfg.TLSConfig{
			ServerName: vmess.SNI,
		}
		if vmess.Alpn != "" {
			ss.TLSSettings.ALPN = cfgcommon.NewStringList([]string{vmess.Alpn})
		}
	}

	return ss
}

func configureGRPC(ss *StreamSettings, vmess *VmessConfig) {
	ss.GRPCSettings = &GRPCSettings{
		ServiceName: vmess.Path,
		MultiMode:   false,
	}
}

func configureQUIC(ss *StreamSettings, vmess *VmessConfig) {
	ss.QUICSettings = &QUICSettings{
		Security: "none",
	}
	if vmess.Type != "" {
		ss.QUICSettings.Header = &Header{
			Type: vmess.Type,
		}
	}
}

func configureHTTP(ss *StreamSettings, vmess *VmessConfig) {
	ss.HTTPSettings = &HTTPSettings{
		Path: vmess.Path,
	}
	if vmess.Host != "" {
		ss.HTTPSettings.Host = []string{vmess.Host}
	}
}

func configureKCP(ss *StreamSettings, vmess *VmessConfig) {
	ss.KCPSettings = &KCPSettings{
		MTU:              1350,
		TTI:              20,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		Congestion:       false,
		ReadBufferSize:   1,
		WriteBufferSize:  1,
	}
	if vmess.Type != "" {
		ss.KCPSettings.Header = &Header{
			Type: vmess.Type,
		}
	}
}

func configureTCP(vmess *VmessConfig, ss *StreamSettings) {
	if vmess.Type == "http" {
		ss.TCPSettings = &TCPSettings{
			Header: &Header{
				Type: "http",
				Request: &HeaderItem{
					Version: "1.1",
					Method:  "GET",
					Path:    []string{vmess.Path},
					Headers: map[string][]string{},
				},
			},
		}
		if vmess.Host != "" {
			ss.TCPSettings.Header.Request.Headers["Host"] = []string{vmess.Host}
		}
	}
}

func configureWS(ss *StreamSettings, vmess *VmessConfig) {
	ss.WSSettings = &WSSettings{
		Path: vmess.Path,
	}
	if vmess.Host != "" {
		ss.WSSettings.Headers = map[string]string{
			"Host": vmess.Host,
		}
	}
}

// StartVmess loads the config and starts a V2Ray instance
func StartVmess(vmessURL string, port int) (*core.Instance, int, error) {

	inst := getServer(vmessURL)
	if inst != nil {
		return inst.Instance, inst.SocksPort, nil
	}

	// Get JSON configuration
	jsonConfig, port, err := VmessToV2Ray(vmessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// Create server config directly using the core.StartInstance function
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start V2Ray instance: %w", err)
	}

	setServer(vmessURL, instance, port)

	return instance, port, nil
}
