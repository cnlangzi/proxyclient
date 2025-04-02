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

// VlessConfig 存储 VLESS URL 参数
type VlessConfig struct {
	UUID        string
	Address     string
	Port        int
	Encryption  string
	Flow        string
	Type        string
	Security    string
	Path        string
	Host        string
	SNI         string
	ALPN        string
	Fingerprint string
	PublicKey   string
	ShortID     string
	SpiderX     string
	ServiceName string
}

// ParseVless 解析 VLESS URL
// vless://uuid@host:port?encryption=none&type=tcp&security=tls&sni=example.com...
func ParseVless(vlessURL string) (*VlessConfig, error) {
	// 移除 vless:// 前缀
	vlessURL = strings.TrimPrefix(vlessURL, "vless://")

	// 解析为标准 URL
	u, err := url.Parse("vless://" + vlessURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}

	// 提取用户信息
	if u.User == nil {
		return nil, fmt.Errorf("missing user info in VLESS URL")
	}
	uuid := u.User.Username()

	// 提取主机和端口
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port in VLESS URL: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in VLESS URL: %w", err)
	}

	// 创建配置
	config := &VlessConfig{
		UUID:       uuid,
		Address:    host,
		Port:       port,
		Encryption: "none", // VLESS 默认加密为 none
		Type:       "tcp",  // 默认传输类型
	}

	// 解析查询参数
	query := u.Query()

	if v := query.Get("encryption"); v != "" {
		config.Encryption = v
	}

	if v := query.Get("flow"); v != "" {
		config.Flow = v
	}

	if v := query.Get("type"); v != "" {
		config.Type = v
		// XHTTP 作为明确支持的类型，但不自动转换
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

	return config, nil
}

// VlessToXRay 将 VLESS URL 转换为 Xray JSON 配置
func VlessToXRay(vlessURL string, port int) ([]byte, int, error) {
	// 解析 VLESS URL
	vless, err := ParseVless(vlessURL)
	if err != nil {
		return nil, 0, err
	}

	// 获取空闲端口（如果未提供）
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// 创建 VLESS 出站配置
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

	// 创建流设置
	streamSettings := &StreamSettings{
		Network:  vless.Type,
		Security: vless.Security,
	}

	// 配置 TLS
	if vless.Security == "tls" {
		streamSettings.TLSSettings = &TLSSettings{
			ServerName:    vless.SNI,
			AllowInsecure: true,
		}

		if vless.Fingerprint != "" {
			streamSettings.TLSSettings.Fingerprint = vless.Fingerprint
		}

		if vless.ALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(vless.ALPN, ",")
		}
	}

	// 配置 XTLS
	if vless.Security == "xtls" {
		streamSettings.Security = "xtls"
		streamSettings.XTLSSettings = &TLSSettings{
			ServerName:    vless.SNI,
			AllowInsecure: true,
		}

		if vless.Fingerprint != "" {
			streamSettings.XTLSSettings.Fingerprint = vless.Fingerprint
		}

		if vless.ALPN != "" {
			streamSettings.XTLSSettings.ALPN = strings.Split(vless.ALPN, ",")
		}
	}

	// 配置 Reality
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

	// 根据传输类型配置
	switch vless.Type {
	case "ws":
		streamSettings.WSSettings = &WSSettings{
			Path: vless.Path,
			Host: vless.Host, // 使用独立的 Host 字段而非 headers
		}

	case "xhttp": // 添加对 XHTTP 的直接支持
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Host:    vless.Host,
			Path:    vless.Path,
			Method:  "GET",
			Version: "h2",
		}

		// 根据 ALPN 设置选择 HTTP 版本
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

	// 创建完整配置
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

	// 转换为 JSON
	buf, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	return buf, port, nil
}

// StartVless 启动 VLESS 客户端并返回 Xray 实例和本地 SOCKS 端口
func StartVless(vlessURL string, port int) (*core.Instance, int, error) {
	// 检查是否已经运行
	server := getServer(vlessURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// 转换为 Xray JSON 配置
	jsonConfig, port, err := VlessToXRay(vlessURL, port)
	if err != nil {
		return nil, 0, err
	}

	// 启动 Xray 实例
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// 注册运行的服务器
	setServer(vlessURL, instance, port)

	fmt.Printf("VLESS proxy started on socks5://127.0.0.1:%d\n", port)
	return instance, port, nil
}
