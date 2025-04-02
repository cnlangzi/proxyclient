package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// SSRConfig 存储 ShadowsocksR URL 参数
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

// ParseSSR 解析 ShadowsocksR URL
// ssr://base64(server:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks)
func ParseSSR(ssrURL string) (*SSRConfig, error) {
	// 移除 ssr:// 前缀
	ssrURL = strings.TrimPrefix(ssrURL, "ssr://")

	// 解码 base64
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(ssrURL)
	if err != nil {
		// 尝试标准 base64
		decoded, err = base64.StdEncoding.DecodeString(ssrURL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode SSR URL: %w", err)
		}
	}

	text := string(decoded)

	// 分离主要部分和参数部分
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

	// 解析主要部分
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid SSR URL format")
	}

	serverPort, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// 解码密码
	password, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[5])
	if err != nil {
		// 尝试标准 base64
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

	// 解析参数部分
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
				// 尝试标准 base64
				decodedValue, err = base64.StdEncoding.DecodeString(value)
				if err != nil {
					// 使用原始值
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

// convertSSRMethod 将 SSR 加密方法转换为 Xray 支持的方法
func convertSSRMethod(method string) (string, error) {
	// Xray 支持的加密方法
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

// isBasicSSR 检查 SSR 配置是否可以由 Xray 处理
func isBasicSSR(config *SSRConfig) bool {
	// 检查支持的协议
	protocol := strings.ToLower(config.Protocol)
	if protocol != "origin" &&
		protocol != "auth_aes128_md5" &&
		protocol != "auth_aes128_sha1" &&
		protocol != "auth_chain_a" {
		fmt.Printf("Unsupported SSR protocol: %s\n", protocol)
		return false
	}

	// 检查支持的混淆
	obfs := strings.ToLower(config.Obfs)
	if obfs != "plain" &&
		obfs != "http_simple" &&
		obfs != "tls1.2_ticket_auth" &&
		obfs != "http_post" {
		fmt.Printf("Unsupported SSR obfuscation: %s\n", obfs)
		return false
	}

	// 检查支持的加密方法
	_, err := convertSSRMethod(config.Method)
	if err != nil {
		fmt.Printf("Unsupported SSR encryption method: %s\n", config.Method)
		return false
	}

	return true
}

// SSRToXRay 将 SSR URL 转换为 Xray JSON 配置
func SSRToXRay(ssrURL string, port int) ([]byte, int, error) {
	// 解析 SSR URL
	ssr, err := ParseSSR(ssrURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse SSR URL: %w", err)
	}

	// 检查配置是否支持
	if !isBasicSSR(ssr) {
		return nil, 0, fmt.Errorf("unsupported SSR configuration (protocol: %s, obfs: %s, method: %s)",
			ssr.Protocol, ssr.Obfs, ssr.Method)
	}

	// 获取空闲端口（如果未提供）
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return nil, 0, err
		}
	}

	// 转换 SSR 方法到 Xray 方法
	xrayMethod, err := convertSSRMethod(ssr.Method)
	if err != nil {
		return nil, 0, err
	}

	// 创建密码与协议/混淆配置
	effectivePassword := ssr.Password

	// 处理协议
	if strings.ToLower(ssr.Protocol) != "origin" {
		effectivePassword = fmt.Sprintf("%s:%s", ssr.Protocol, effectivePassword)
		if ssr.ProtocolParam != "" {
			effectivePassword = fmt.Sprintf("%s?protocolparam=%s", effectivePassword, ssr.ProtocolParam)
		}
	}

	// 处理混淆
	if strings.ToLower(ssr.Obfs) != "plain" {
		effectivePassword = fmt.Sprintf("%s:%s", ssr.Obfs, effectivePassword)
		if ssr.ObfsParam != "" {
			effectivePassword = fmt.Sprintf("%s?obfsparam=%s", effectivePassword, ssr.ObfsParam)
		}
	}

	// Shadowsocks 出站设置
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

	// 创建基于 Xray JSON 格式的配置
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

	// 转换为 JSON
	buf, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	return buf, port, nil
}

// StartSSR 启动 SSR 客户端并返回 Xray 实例和本地 SOCKS 端口
func StartSSR(ssrURL string, port int) (*core.Instance, int, error) {
	// 检查是否已经运行
	server := getServer(ssrURL)
	if server != nil {
		return server.Instance, server.SocksPort, nil
	}

	// 转换为 Xray JSON 配置
	jsonConfig, port, err := SSRToXRay(ssrURL, port)
	if err != nil {
		return nil, 0, err
	}

	// 启动 Xray 实例
	instance, err := core.StartInstance("json", jsonConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start Xray instance: %w", err)
	}

	// 注册运行的服务器
	setServer(ssrURL, instance, port)

	fmt.Printf("SSR proxy started on socks5://127.0.0.1:%d\n", port)
	return instance, port, nil
}
