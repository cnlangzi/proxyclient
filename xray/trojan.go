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

// TrojanConfig 存储 Trojan URL 参数
type TrojanConfig struct {
	Password    string
	Address     string
	Port        int
	Flow        string
	Type        string
	Security    string
	Path        string
	Host        string
	SNI         string
	ALPN        string
	Fingerprint string
	ServiceName string
}

// ParseTrojan 解析 Trojan URL
// trojan://password@host:port?security=tls&type=tcp&sni=example.com...
func ParseTrojan(trojanURL string) (*TrojanConfig, error) {
	// 移除 trojan:// 前缀
	trojanURL = strings.TrimPrefix(trojanURL, "trojan://")

	// 解析为标准 URL
	u, err := url.Parse("trojan://" + trojanURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Trojan URL: %w", err)
	}

	// 提取用户信息
	if u.User == nil {
		return nil, fmt.Errorf("missing password in Trojan URL")
	}
	password := u.User.Username()

	// 提取主机和端口
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port in Trojan URL: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in Trojan URL: %w", err)
	}

	// 创建配置
	config := &TrojanConfig{
		Password: password,
		Address:  host,
		Port:     port,
		Security: "tls", // Trojan 默认使用 TLS
		Type:     "tcp", // 默认传输类型
	}

	// 解析查询参数
	query := u.Query()

	if v := query.Get("flow"); v != "" {
		config.Flow = v
	}

	if v := query.Get("type"); v != "" {
		config.Type = v
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
	} else {
		config.SNI = host
	}

	if v := query.Get("alpn"); v != "" {
		config.ALPN = v
	}

	if v := query.Get("fp"); v != "" {
		config.Fingerprint = v
	}

	if v := query.Get("serviceName"); v != "" {
		config.ServiceName = v
	}

	return config, nil
}

// TrojanToXRay 将 Trojan URL 转换为 Xray JSON 配置
func TrojanToXRay(trojanURL string, port int) ([]byte, int, error) {
	// 解析 Trojan URL
	trojan, err := ParseTrojan(trojanURL)
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

	// 创建 Trojan 出站配置
	trojanSettings := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"address":  trojan.Address,
				"port":     trojan.Port,
				"password": trojan.Password,
				"flow":     trojan.Flow,
				"level":    0,
			},
		},
	}

	// 创建流设置
	streamSettings := &StreamSettings{
		Network:  trojan.Type,
		Security: trojan.Security,
	}

	// 配置 TLS
	if trojan.Security == "tls" {
		streamSettings.TLSSettings = &TLSSettings{
			ServerName:    trojan.SNI,
			AllowInsecure: true,
		}

		if trojan.Fingerprint != "" {
			streamSettings.TLSSettings.Fingerprint = trojan.Fingerprint
		}

		if trojan.ALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(trojan.ALPN, ",")
		}
	}

	// 根据传输类型配置
	switch trojan.Type {
	case "ws":
		streamSettings.WSSettings = &WSSettings{
			Path: trojan.Path,
			Host: trojan.Host,
		}
	case "xhttp": // 明确指定使用 XHTTP
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Host:    trojan.Host,
			Path:    trojan.Path,
			Method:  "GET",
			Version: "h2",
		}

		// 根据 ALPN 设置选择 HTTP 版本
		if trojan.ALPN != "" {
			if strings.Contains(trojan.ALPN, "h3") {
				streamSettings.XHTTPSettings.Version = "h3"
			}
		}
	case "tcp":
		if trojan.Host != "" || trojan.Path != "" {
			streamSettings.TCPSettings = &TCPSettings{
				Header: &Header{
					Type: "http",
					Request: map[string]interface{}{
						"path": []string{trojan.Path},
						"headers": map[string]interface{}{
							"Host": []string{trojan.Host},
						},
					},
				},
			}
		}
	case "grpc":
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: trojan.ServiceName,
			MultiMode:   false,
		}
	case "http":
		streamSettings.HTTPSettings = &HTTPSettings{
			Path: trojan.Path,
		}
		if trojan.Host != "" {
			streamSettings.HTTPSettings.Host = []string{trojan.Host}
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

	// 转换为 JSON
	buf, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	return buf, port, nil
}

// StartTrojan 启动 Trojan 客户端并返回 Xray 实例和本地 SOCKS 端口
func StartTrojan(trojanURL string, port int) (*core.Instance, int, error) {
	// 检查是否已经运行
	server := getServer(trojanURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// 转换为 Xray JSON 配置
	jsonConfig, port, err := TrojanToXRay(trojanURL, port)
	if err != nil {
		return nil, 0, err
	}

	// 启动 Xray 实例
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// 注册运行的服务器
	setServer(trojanURL, instance, port)

	fmt.Printf("Trojan proxy started on socks5://127.0.0.1:%d\n", port)
	return instance, port, nil
}
