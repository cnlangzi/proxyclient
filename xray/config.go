package xray

// 通用配置结构体，与 Xray 配置格式匹配
type XRayConfig struct {
	Log       *LogConfig     `json:"log,omitempty"`
	DNS       *DNSConfig     `json:"dns,omitempty"`
	Routing   *RoutingConfig `json:"routing,omitempty"`
	Inbounds  []Inbound      `json:"inbounds"`
	Outbounds []Outbound     `json:"outbounds"`
}

type LogConfig struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	Loglevel string `json:"loglevel,omitempty"`
}

type DNSConfig struct {
	Servers []string `json:"servers,omitempty"`
}

type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy,omitempty"`
	Rules          []RoutingRule `json:"rules,omitempty"`
}

type RoutingRule struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
}

type Inbound struct {
	Tag      string      `json:"tag"`
	Port     int         `json:"port"`
	Listen   string      `json:"listen,omitempty"`
	Protocol string      `json:"protocol"`
	Settings interface{} `json:"settings"`
	Sniffing *Sniffing   `json:"sniffing,omitempty"`
}

type Outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *Mux            `json:"mux,omitempty"`
}

type Sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type SocksSetting struct {
	Auth      string `json:"auth,omitempty"`
	UDP       bool   `json:"udp,omitempty"`
	IP        string `json:"ip,omitempty"`
	UserLevel int    `json:"userLevel,omitempty"`
}

type StreamSettings struct {
	Network         string           `json:"network,omitempty"`
	Security        string           `json:"security,omitempty"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	TCPSettings     *TCPSettings     `json:"tcpSettings,omitempty"`
	KCPSettings     *KCPSettings     `json:"kcpSettings,omitempty"`
	WSSettings      *WSSettings      `json:"wsSettings,omitempty"`
	HTTPSettings    *HTTPSettings    `json:"httpSettings,omitempty"`
	QUICSettings    *QUICSettings    `json:"quicSettings,omitempty"`
	GRPCSettings    *GRPCSettings    `json:"grpcSettings,omitempty"`
	XTLSSettings    *TLSSettings     `json:"xtlsSettings,omitempty"`    // 新增 XTLS 支持
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"` // 新增 Reality 支持
	XHTTPSettings   *XHTTPSettings   `json:"xhttpSettings,omitempty"`   // 新增 XHTTP 支持
}

type RealitySettings struct {
	Show        bool   `json:"show,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type TLSSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
}

type TCPSettings struct {
	Header *Header `json:"header,omitempty"`
}

type Header struct {
	Type     string      `json:"type,omitempty"`
	Request  interface{} `json:"request,omitempty"`
	Response interface{} `json:"response,omitempty"`
}

type KCPSettings struct {
	MTU              int     `json:"mtu,omitempty"`
	TTI              int     `json:"tti,omitempty"`
	UplinkCapacity   int     `json:"uplinkCapacity,omitempty"`
	DownlinkCapacity int     `json:"downlinkCapacity,omitempty"`
	Congestion       bool    `json:"congestion,omitempty"`
	ReadBufferSize   int     `json:"readBufferSize,omitempty"`
	WriteBufferSize  int     `json:"writeBufferSize,omitempty"`
	Header           *Header `json:"header,omitempty"`
}

// 更新 WSSettings 结构体
type WSSettings struct {
	Path    string            `json:"path,omitempty"`
	Host    string            `json:"host,omitempty"` // 新增独立的 Host 字段
	Headers map[string]string `json:"headers,omitempty"`
}

type HTTPSettings struct {
	Path string   `json:"path,omitempty"`
	Host []string `json:"host,omitempty"`
}

type QUICSettings struct {
	Security string  `json:"security,omitempty"`
	Key      string  `json:"key,omitempty"`
	Header   *Header `json:"header,omitempty"`
}

type GRPCSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type Mux struct {
	Enabled     bool   `json:"enabled"`
	Concurrency int    `json:"concurrency,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

// 添加新的 XHTTP 设置结构体
type XHTTPSettings struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Version string            `json:"version,omitempty"` // "h2" 或 "h3"
}
