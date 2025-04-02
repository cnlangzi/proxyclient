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

// VmessConfig 存储 VMess URL 参数
type VmessConfig struct {
	V        string    `json:"v"`
	PS       string    `json:"ps"`       // 备注
	Add      string    `json:"add"`      // 地址
	Port     IntString `json:"port"`     // 端口
	ID       string    `json:"id"`       // UUID
	Aid      IntString `json:"aid"`      // AlterID
	Net      string    `json:"net"`      // 传输协议
	Type     string    `json:"type"`     // 伪装类型
	Host     string    `json:"host"`     // 伪装域名
	Path     string    `json:"path"`     // WebSocket 路径
	TLS      string    `json:"tls"`      // TLS
	SNI      string    `json:"sni"`      // TLS SNI
	Alpn     string    `json:"alpn"`     // ALPN
	Flow     string    `json:"flow"`     // XTLS Flow
	Fp       string    `json:"fp"`       // 指纹
	PbK      string    `json:"pbk"`      // PublicKey (Reality)
	Sid      string    `json:"sid"`      // ShortID (Reality)
	SpX      string    `json:"spx"`      // SpiderX (Reality)
	Security string    `json:"security"` // 加密方法
	XHTTPVer string    `json:"xver"`     // XHTTP 版本，"h2" 或 "h3"
}

// IntString 处理整数或字符串类型
type IntString struct {
	value string
}

func (i *IntString) UnmarshalJSON(b []byte) error {
	i.value = string(b)
	return nil
}

func (i IntString) Value() int {
	if i.value == "" {
		return 0
	}

	// 尝试移除引号
	value := strings.Trim(i.value, "\"")

	var v int
	_, err := fmt.Sscanf(value, "%d", &v)
	if err != nil {
		return 0
	}
	return v
}

// VmessToXRay 将 VMess URL 转换为 Xray JSON 配置
func VmessToXRay(vmessURL string, port int) ([]byte, int, error) {
	// 删除 vmess:// 前缀
	encoded := strings.TrimPrefix(vmessURL, "vmess://")

	// Base64 解码
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	// 解析为 VMessConfig
	var vmess VmessConfig
	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return nil, 0, fmt.Errorf("JSON parsing failed: %w", err)
	}

	// 如果 vmess.Net 是 "xhttp"，我们应该正确处理
	// 这通常应该在 base64 解码后的 JSON 处理部分

	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// 生成完整的 Xray 配置
	config := createCompleteVmessConfig(&vmess, port)

	// 返回 JSON 格式
	buf, err := json.MarshalIndent(config, "", "  ")
	return buf, port, err
}

func base64Decode(encoded string) ([]byte, error) {
	// 支持不同的编码方法
	if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func createCompleteVmessConfig(vmess *VmessConfig, port int) *XRayConfig {
	// 如果是 WebSocket 且满足自动转换条件，则优先使用 XHTTP
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
									"flow":     vmess.Flow, // XTLS Flow 支持
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

// 修改 buildEnhancedStreamSettings 函数
func buildEnhancedStreamSettings(vmess *VmessConfig) *StreamSettings {
	ss := &StreamSettings{
		Network:  vmess.Net,
		Security: vmess.TLS,
	}

	// 配置 TLS
	if vmess.TLS == "tls" {
		ss.TLSSettings = &TLSSettings{
			ServerName:    vmess.Host,
			AllowInsecure: true,
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

	// 配置 XTLS
	if vmess.TLS == "xtls" {
		ss.Security = "xtls"
		ss.XTLSSettings = &TLSSettings{
			ServerName:    vmess.Host,
			AllowInsecure: true,
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

	// 配置 Reality
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

	// 根据网络类型配置相应设置
	switch vmess.Net {
	case "ws":
		// 保留原有的 WebSocket 处理
		configureWS(ss, vmess)

	case "xhttp": // 添加对明确指定使用 XHTTP 的支持
		configureXHTTP(ss, vmess)
	// ... 保留其他传输类型的配置代码 ...
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

// 添加 XHTTP 配置函数
func configureXHTTP(ss *StreamSettings, vmess *VmessConfig) {
	ss.XHTTPSettings = &XHTTPSettings{
		Host:    vmess.Host,
		Path:    vmess.Path,
		Method:  "GET",
		Version: "h2", // 默认使用 HTTP/2
	}

	// 根据可能的 ALPN 设置选择 HTTP 版本
	if vmess.Alpn != "" {
		if strings.Contains(vmess.Alpn, "h3") {
			ss.XHTTPSettings.Version = "h3"
		}
	}
}

// 保留原有的 WebSocket 配置，但修改为使用独立的 host 字段
func configureWS(ss *StreamSettings, vmess *VmessConfig) {
	ss.WSSettings = &WSSettings{
		Path: vmess.Path,
		Host: vmess.Host, // 使用独立的 Host 字段
	}

	// 保留其他可能的 headers，但不放 Host
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

// StartVmess 启动 VMess 客户端
func StartVmess(vmessURL string, port int) (*core.Instance, int, error) {
	// 检查是否已经运行
	server := getServer(vmessURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// 获取 JSON 配置
	jsonConfig, port, err := VmessToXRay(vmessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// 直接使用 Xray 的 StartInstance 函数创建服务器配置
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	setServer(vmessURL, instance, port)

	return instance, port, nil
}
