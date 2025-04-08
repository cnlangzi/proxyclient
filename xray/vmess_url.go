package xray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	// Register the VMESS url parser
	proxyclient.RegisterParser("vmess", func(u *url.URL) (proxyclient.URL, error) {
		return ParseVmessURL(u)
	})
}

// VmessConfig stores VMess URL parameters
type VmessConfig struct {
	V             string          `json:"v"`
	PS            string          `json:"ps"`               // Remarks
	Add           string          `json:"add"`              // Address
	Port          proxyclient.Int `json:"port"`             // Port
	ID            string          `json:"id"`               // UUID
	Aid           proxyclient.Int `json:"aid"`              // AlterID
	Net           string          `json:"net"`              // Transport protocol
	Type          string          `json:"type"`             // Camouflage type
	Host          string          `json:"host"`             // Camouflage domain
	Path          string          `json:"path"`             // WebSocket path
	TLS           string          `json:"tls"`              // TLS
	SNI           string          `json:"sni"`              // TLS SNI
	Alpn          string          `json:"alpn"`             // ALPN
	Flow          string          `json:"flow"`             // XTLS Flow
	Fp            string          `json:"fp"`               // Fingerprint
	PbK           string          `json:"pbk"`              // PublicKey (Reality)
	Sid           string          `json:"sid"`              // ShortID (Reality)
	SpX           string          `json:"spx"`              // SpiderX (Reality)
	Security      string          `json:"security"`         // Encryption method
	XHTTPVer      string          `json:"xver"`             // XHTTP version, "h2" or "h3"
	AllowInsecure bool            `json:"skip_cert_verify"` // Controls whether to allow insecure TLS connections

	raw *url.URL `json:"-"`
}

type VmessURL struct {
	Config *VmessConfig
}

func (v *VmessURL) Raw() *url.URL {
	return v.Config.raw
}

func (v *VmessURL) Opaque() string {
	return strings.TrimPrefix(v.Config.raw.String(), "vmess://")
}

func (v *VmessURL) Host() string {
	return v.Config.Add
}

func (v *VmessURL) Port() string {
	return strconv.Itoa(v.Config.Port.Value())
}

func (v *VmessURL) Protocol() string {
	return "vmess"
}

func (v *VmessURL) User() string {
	return v.Config.ID
}

func (v *VmessURL) Password() string {
	return ""
}

func ParseVmessURL(u *url.URL) (*VmessURL, error) {

	vmessURL := u.String()

	// Remove vmess:// prefix
	encoded := strings.TrimPrefix(vmessURL, "vmess://")

	// Base64 decode
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse to VMessConfig
	vmess := &VmessConfig{
		AllowInsecure: true,
	}

	if err := json.Unmarshal(decoded, vmess); err != nil {
		return nil, fmt.Errorf("JSON parsing failed: %w", err)
	}

	vmess.raw = u

	return &VmessURL{
		Config: vmess,
	}, nil
}
