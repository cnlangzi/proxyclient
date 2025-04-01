package v2ray

import "github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"

// Complete v2ray configuration structure
type V2RayConfig struct {
	Log       *LogConfig     `json:"log,omitempty"`
	DNS       *DNSConfig     `json:"dns,omitempty"`
	Routing   *RoutingConfig `json:"routing,omitempty"`
	Inbounds  []Inbound      `json:"inbounds"`
	Outbounds []Outbound     `json:"outbounds"`
	Policy    *PolicyConfig  `json:"policy,omitempty"`
	Stats     *StatsConfig   `json:"stats,omitempty"`
	Reverse   *ReverseConfig `json:"reverse,omitempty"`
}

type LogConfig struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	Loglevel string `json:"loglevel,omitempty"`
}

type DNSConfig struct {
	Servers []interface{} `json:"servers,omitempty"`
	Hosts   interface{}   `json:"hosts,omitempty"`
}

type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy,omitempty"`
	Rules          []RoutingRule `json:"rules,omitempty"`
}

type RoutingRule struct {
	Type        string   `json:"type,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	SourcePort  string   `json:"sourcePort,omitempty"`
	Network     string   `json:"network,omitempty"`
	Source      []string `json:"source,omitempty"`
	User        []string `json:"user,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
}

type Inbound struct {
	Tag            string          `json:"tag,omitempty"`
	Port           int             `json:"port"`
	Listen         string          `json:"listen,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Sniffing       *Sniffing       `json:"sniffing,omitempty"`
}

type SocksSetting struct {
	Auth      string `json:"auth"`
	UDP       bool   `json:"udp"`
	IP        string `json:"ip,omitempty"`
	UserLevel int    `json:"userLevel,omitempty"`
}

type HttpSetting struct {
	Timeout          int  `json:"timeout,omitempty"`
	AllowTransparent bool `json:"allowTransparent,omitempty"`
	UserLevel        int  `json:"userLevel,omitempty"`
}

type Sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type Outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	ProxySettings  *ProxySettings  `json:"proxySettings,omitempty"`
	Mux            *Mux            `json:"mux,omitempty"`
}

type ProxySettings struct {
	Tag            string `json:"tag"`
	TransportLayer bool   `json:"transportLayer,omitempty"`
}

type VMessOutboundSetting struct {
	Vnext []VNext `json:"vnext"`
}

type VNext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []User `json:"users"`
}

type User struct {
	ID       string `json:"id"`
	AlterID  int    `json:"alterId"`
	Security string `json:"security"`
	Level    int    `json:"level,omitempty"`
}

type StreamSettings struct {
	Network      string            `json:"network"`
	Security     string            `json:"security"`
	WSSettings   *WSSettings       `json:"wsSettings,omitempty"`
	TCPSettings  *TCPSettings      `json:"tcpSettings,omitempty"`
	KCPSettings  *KCPSettings      `json:"kcpSettings,omitempty"`
	HTTPSettings *HTTPSettings     `json:"httpSettings,omitempty"`
	QUICSettings *QUICSettings     `json:"quicSettings,omitempty"`
	TLSSettings  *tlscfg.TLSConfig `json:"tlsSettings,omitempty"`
	GRPCSettings *GRPCSettings     `json:"grpcSettings,omitempty"`
}

type WSSettings struct {
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"maxEarlyData,omitempty"`
	EarlyDataHeaderName string            `json:"earlyDataHeaderName,omitempty"`
}

type TCPSettings struct {
	Header *Header `json:"header,omitempty"`
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
	Seed             string  `json:"seed,omitempty"`
}

type HTTPSettings struct {
	Host    []string          `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type QUICSettings struct {
	Security string  `json:"security,omitempty"`
	Key      string  `json:"key,omitempty"`
	Header   *Header `json:"header,omitempty"`
}

type GRPCSettings struct {
	ServiceName         string `json:"serviceName,omitempty"`
	MultiMode           bool   `json:"multiMode,omitempty"`
	IdleTimeout         int    `json:"idle_timeout,omitempty"`
	HealthCheckTimeout  int    `json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool   `json:"permit_without_stream,omitempty"`
}

type Header struct {
	Type     string      `json:"type,omitempty"`
	Request  *HeaderItem `json:"request,omitempty"`
	Response *HeaderItem `json:"response,omitempty"`
}

type HeaderItem struct {
	Version string              `json:"version,omitempty"`
	Method  string              `json:"method,omitempty"`
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type Mux struct {
	Enabled     bool   `json:"enabled"`
	Concurrency int    `json:"concurrency,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

type PolicyConfig struct {
	Levels map[string]Level `json:"levels,omitempty"`
	System *SystemPolicy    `json:"system,omitempty"`
}

type Level struct {
	HandshakeTimeout  int  `json:"handshake,omitempty"`
	ConnIdle          int  `json:"connIdle,omitempty"`
	UplinkOnly        int  `json:"uplinkOnly,omitempty"`
	DownlinkOnly      int  `json:"downlinkOnly,omitempty"`
	BufferSize        int  `json:"bufferSize,omitempty"`
	StatsUserUplink   bool `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool `json:"statsUserDownlink,omitempty"`
}

type SystemPolicy struct {
	StatsInboundUplink    bool `json:"statsInboundUplink,omitempty"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink,omitempty"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink,omitempty"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink,omitempty"`
}

type StatsConfig struct{}

type ReverseConfig struct{}
