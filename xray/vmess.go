package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// VmessConfig stores VMess URL parameters
type VmessConfig struct {
	V             string              `json:"v"`
	PS            string              `json:"ps"`               // Remarks
	Add           string              `json:"add"`              // Address
	Port          proxyclient.JsonInt `json:"port"`             // Port
	ID            string              `json:"id"`               // UUID
	Aid           proxyclient.JsonInt `json:"aid"`              // AlterID
	Net           string              `json:"net"`              // Transport protocol
	Type          string              `json:"type"`             // Camouflage type
	Host          string              `json:"host"`             // Camouflage domain
	Path          string              `json:"path"`             // WebSocket path
	TLS           string              `json:"tls"`              // TLS
	SNI           string              `json:"sni"`              // TLS SNI
	Alpn          string              `json:"alpn"`             // ALPN
	Flow          string              `json:"flow"`             // XTLS Flow
	Fp            string              `json:"fp"`               // Fingerprint
	PbK           string              `json:"pbk"`              // PublicKey (Reality)
	Sid           string              `json:"sid"`              // ShortID (Reality)
	SpX           string              `json:"spx"`              // SpiderX (Reality)
	Security      string              `json:"security"`         // Encryption method
	XHTTPVer      string              `json:"xver"`             // XHTTP version, "h2" or "h3"
	AllowInsecure bool                `json:"skip_cert_verify"` // Controls whether to allow insecure TLS connections
}

// VmessToXRay converts VMess URL to Xray JSON configuration
func VmessToXRay(vmessURL string, port int) ([]byte, int, error) {
	// Remove vmess:// prefix
	encoded := strings.TrimPrefix(vmessURL, "vmess://")

	// Base64 decode
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse to VMessConfig
	vmess := &VmessConfig{
		AllowInsecure: true,
	}

	if err := json.Unmarshal(decoded, vmess); err != nil {
		return nil, 0, fmt.Errorf("JSON parsing failed: %w", err)
	}

	// If vmess.Net is "xhttp", we should handle it properly
	// This should typically be in the JSON processing part after base64 decoding

	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// Generate complete Xray configuration
	config := createCompleteVmessConfig(vmess, port)

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

func createCompleteVmessConfig(vmess *VmessConfig, port int) *XRayConfig {
	// If it's WebSocket and meets the auto-conversion conditions, prioritize using XHTTP
	if vmess.Net == "ws" && vmess.XHTTPVer != "" {
		vmess.Net = "xhttp"
	}

	return &XRayConfig{
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
				Tag:      "vmess-out",
				Protocol: "vmess",
				Settings: map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": vmess.Add,
							"port":    vmess.Port.Value(),
							"users": []map[string]interface{}{
								{
									"id":       vmess.ID,
									"alterId":  vmess.Aid.Value(),
									"security": getSecurityMethod(vmess),
									"level":    0,
									"flow":     vmess.Flow, // XTLS Flow support
								},
							},
						},
					},
				},
				StreamSettings: buildEnhancedStreamSettings(vmess),
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
		// DomainStrategy: "AsIs",
		// Rules: []RoutingRule{
		// 	{
		// 		Type:        "field",
		// 		OutboundTag: "direct",
		// 		IP:          []string{"geoip:private"},
		// 	},
		// },
		// },
	}
}

func getSecurityMethod(vmess *VmessConfig) string {
	if vmess.Security != "" {
		return vmess.Security
	}
	return "auto"
}

// Modified buildEnhancedStreamSettings function
func buildEnhancedStreamSettings(vmess *VmessConfig) *StreamSettings {
	ss := &StreamSettings{
		Network:  vmess.Net,
		Security: vmess.TLS,
	}

	// Configure TLS
	if vmess.TLS == "tls" {
		ss.TLSSettings = &TLSSettings{
			ServerName:    vmess.Host,
			AllowInsecure: vmess.AllowInsecure, // Use the value read from configuration
		}

		if vmess.SNI != "" {
			ss.TLSSettings.ServerName = vmess.SNI
		}

		if vmess.Alpn != "" {
			ss.TLSSettings.ALPN = strings.Split(vmess.Alpn, ",")
		}

		if vmess.Fp != "" {
			ss.TLSSettings.Fingerprint = vmess.Fp
		}
	}

	// Configure XTLS
	if vmess.TLS == "xtls" {
		ss.Security = "xtls"
		ss.XTLSSettings = &TLSSettings{
			ServerName:    vmess.Host,
			AllowInsecure: vmess.AllowInsecure, // Use the value read from configuration
		}

		if vmess.SNI != "" {
			ss.XTLSSettings.ServerName = vmess.SNI
		}

		if vmess.Alpn != "" {
			ss.XTLSSettings.ALPN = strings.Split(vmess.Alpn, ",")
		}

		if vmess.Fp != "" {
			ss.XTLSSettings.Fingerprint = vmess.Fp
		}
	}

	// Configure Reality
	if vmess.TLS == "reality" {
		ss.Security = "reality"
		ss.RealitySettings = &RealitySettings{
			ServerName:  vmess.SNI,
			Fingerprint: vmess.Fp,
			PublicKey:   vmess.PbK,
			ShortID:     vmess.Sid,
			SpiderX:     vmess.SpX,
		}
	}

	// Configure settings based on network type
	switch vmess.Net {
	case "ws":
		// Retain original WebSocket handling
		configureWS(ss, vmess)

	case "xhttp": // Add support for explicitly using XHTTP
		configureXHTTP(ss, vmess)
	case "kcp":
		configureKCP(ss, vmess)
	case "tcp":
		configureTCP(ss, vmess)
	case "http", "h2":
		configureHTTP(ss, vmess)
	case "quic":
		configureQUIC(ss, vmess)
	case "grpc":
		configureGRPC(ss, vmess)
	}

	return ss
}

// Add XHTTP configuration function
func configureXHTTP(ss *StreamSettings, vmess *VmessConfig) {
	ss.XHTTPSettings = &XHTTPSettings{
		Host:    vmess.Host,
		Path:    vmess.Path,
		Method:  "GET",
		Version: "h2", // Default to HTTP/2
	}

	// Select HTTP version based on possible ALPN settings
	if vmess.Alpn != "" {
		if strings.Contains(vmess.Alpn, "h3") {
			ss.XHTTPSettings.Version = "h3"
		}
	}
}

// Retain the original WebSocket configuration, but modify to use the independent host field
func configureWS(ss *StreamSettings, vmess *VmessConfig) {
	ss.WSSettings = &WSSettings{
		Path: vmess.Path,
		Host: vmess.Host, // Use independent Host field
	}

	// Retain other possible headers, but don't include Host
	if vmess.Host != "" && len(ss.WSSettings.Headers) > 0 {
		delete(ss.WSSettings.Headers, "Host")
		if len(ss.WSSettings.Headers) == 0 {
			ss.WSSettings.Headers = nil
		}
	}
}

func configureTCP(ss *StreamSettings, vmess *VmessConfig) {
	if vmess.Type == "http" {
		ss.TCPSettings = &TCPSettings{
			Header: &Header{
				Type: "http",
				Request: map[string]interface{}{
					"path": []string{vmess.Path},
					"headers": map[string]interface{}{
						"Host": []string{vmess.Host},
					},
				},
			},
		}
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

func configureHTTP(ss *StreamSettings, vmess *VmessConfig) {
	ss.HTTPSettings = &HTTPSettings{
		Path: vmess.Path,
	}

	if vmess.Host != "" {
		ss.HTTPSettings.Host = []string{vmess.Host}
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

func configureGRPC(ss *StreamSettings, vmess *VmessConfig) {
	ss.GRPCSettings = &GRPCSettings{
		ServiceName: vmess.Path,
		MultiMode:   false,
	}
}

// StartVmess starts a VMess client
func StartVmess(vmessURL string, port int) (*core.Instance, int, error) {
	// Check if already running
	server := getServer(vmessURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// Get JSON configuration
	jsonConfig, port, err := VmessToXRay(vmessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// Directly use Xray's StartInstance function to create server configuration
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	setServer(vmessURL, instance, port)

	return instance, port, nil
}
