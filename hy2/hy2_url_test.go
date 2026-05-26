package hy2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHY2URL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *HY2Config
		wantErr bool
	}{
		{
			name:  "basic hysteria2 URL",
			input: "hysteria2://password@example.com:443",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "example.com",
				Remark:  "",
			},
		},
		{
			name:  "basic hy2 short form",
			input: "hy2://password@example.com:443",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "example.com",
				Remark:  "",
			},
		},
		{
			name:  "with sni parameter",
			input: "hysteria2://password@example.com:443/?sni=custom.sni.com",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "custom.sni.com",
			},
		},
		{
			name:  "with insecure=true",
			input: "hysteria2://password@example.com:443/?insecure=true",
			want: &HY2Config{
				Auth:     "password",
				Address:  "example.com",
				Port:     443,
				SNI:      "example.com",
				Insecure: true,
			},
		},
		{
			name:  "with salamander obfuscation",
			input: "hysteria2://password@example.com:443/?obfs=salamander&obfs-password=secret123",
			want: &HY2Config{
				Auth:         "password",
				Address:      "example.com",
				Port:         443,
				SNI:          "example.com",
				ObfsType:     "salamander",
				ObfsPassword: "secret123",
			},
		},
		{
			name:  "with gecko obfuscation",
			input: "hysteria2://password@example.com:443/?obfs=gecko&obfs-password=secret123&obfs-min-packet-size=512&obfs-max-packet-size=1200",
			want: &HY2Config{
				Auth:              "password",
				Address:           "example.com",
				Port:              443,
				SNI:               "example.com",
				ObfsType:          "gecko",
				ObfsPassword:      "secret123",
				ObfsMinPacketSize: 512,
				ObfsMaxPacketSize: 1200,
			},
		},
		{
			name:  "with bandwidth",
			input: "hysteria2://password@example.com:443/?up=100 mbps&down=200 mbps",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "example.com",
				Up:      "100 mbps",
				Down:    "200 mbps",
			},
		},
		{
			name:  "with fastopen",
			input: "hysteria2://password@example.com:443/?fastopen=true",
			want: &HY2Config{
				Auth:     "password",
				Address:  "example.com",
				Port:     443,
				SNI:      "example.com",
				FastOpen: true,
			},
		},
		{
			name:  "with fragment (remark)",
			input: "hysteria2://password@example.com:443/?sni=test.com#my-remark",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "test.com",
				Remark:  "my-remark",
			},
		},
		{
			name:  "no port defaults to 443",
			input: "hysteria2://password@example.com",
			want: &HY2Config{
				Auth:    "password",
				Address: "example.com",
				Port:    443,
				SNI:     "example.com",
			},
		},
		{
			name:  "all parameters combined",
			input: "hysteria2://mypassword@example.com:8443/?sni=custom.com&insecure=true&obfs=salamander&obfs-password=obfs123&up=50 mbps&down=100 mbps&fastopen=true#server1",
			want: &HY2Config{
				Auth:         "mypassword",
				Address:      "example.com",
				Port:         8443,
				SNI:          "custom.com",
				Insecure:     true,
				ObfsType:     "salamander",
				ObfsPassword: "obfs123",
				Up:           "50 mbps",
				Down:         "100 mbps",
				FastOpen:     true,
				Remark:       "server1",
			},
		},
		{
			name:  "insecure=1",
			input: "hysteria2://password@example.com:443/?insecure=1",
			want: &HY2Config{
				Auth:     "password",
				Address:  "example.com",
				Port:     443,
				SNI:      "example.com",
				Insecure: true,
			},
		},
		{
			name:  "fastopen=1",
			input: "hysteria2://password@example.com:443/?fastopen=1",
			want: &HY2Config{
				Auth:     "password",
				Address:  "example.com",
				Port:     443,
				SNI:      "example.com",
				FastOpen: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)
			assert.NoError(t, err)

			got, err := ParseHY2URL(u)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.NotNil(t, got.Config)

			cfg := got.Config
			assert.Equal(t, tt.want.Auth, cfg.Auth, "Auth mismatch")
			assert.Equal(t, tt.want.Address, cfg.Address, "Address mismatch")
			assert.Equal(t, tt.want.Port, cfg.Port, "Port mismatch")
			assert.Equal(t, tt.want.SNI, cfg.SNI, "SNI mismatch")
			assert.Equal(t, tt.want.Insecure, cfg.Insecure, "Insecure mismatch")
			assert.Equal(t, tt.want.ObfsType, cfg.ObfsType, "ObfsType mismatch")
			assert.Equal(t, tt.want.ObfsPassword, cfg.ObfsPassword, "ObfsPassword mismatch")
			assert.Equal(t, tt.want.ObfsMinPacketSize, cfg.ObfsMinPacketSize, "ObfsMinPacketSize mismatch")
			assert.Equal(t, tt.want.ObfsMaxPacketSize, cfg.ObfsMaxPacketSize, "ObfsMaxPacketSize mismatch")
			assert.Equal(t, tt.want.Up, cfg.Up, "Up mismatch")
			assert.Equal(t, tt.want.Down, cfg.Down, "Down mismatch")
			assert.Equal(t, tt.want.FastOpen, cfg.FastOpen, "FastOpen mismatch")
			assert.Equal(t, tt.want.Remark, cfg.Remark, "Remark mismatch")
		})
	}
}

func TestHY2URLInterface(t *testing.T) {
	u, err := url.Parse("hysteria2://password@example.com:443/?sni=test.com&insecure=true#my-server")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)

	// Test all interface methods
	assert.Equal(t, "hysteria2", hy2URL.Protocol())
	assert.Equal(t, "example.com", hy2URL.Host())
	assert.Equal(t, "443", hy2URL.Port())
	assert.Equal(t, "password", hy2URL.Password())
	assert.Equal(t, "", hy2URL.User())
	assert.Equal(t, "my-server", hy2URL.Name())

	raw := hy2URL.Raw()
	assert.NotNil(t, raw)
	assert.Equal(t, "hysteria2", raw.Scheme)
}

func TestHY2URLInterfaceHy2(t *testing.T) {
	u, err := url.Parse("hy2://password@example.com:443/?sni=test.com&insecure=true#my-server")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)

	// Test all interface methods - scheme should be "hy2" not "hysteria2"
	assert.Equal(t, "hy2", hy2URL.Protocol())
	assert.Equal(t, "example.com", hy2URL.Host())
	assert.Equal(t, "443", hy2URL.Port())
	assert.Equal(t, "password", hy2URL.Password())
	assert.Equal(t, "", hy2URL.User())
	assert.Equal(t, "my-server", hy2URL.Name())

	raw := hy2URL.Raw()
	assert.NotNil(t, raw)
	assert.Equal(t, "hy2", raw.Scheme)
}

func TestHY2URLOpaque(t *testing.T) {
	u, err := url.Parse("hysteria2://password@example.com:443/")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)

	// Opaque should return the URL without the scheme prefix
	assert.Contains(t, hy2URL.Opaque(), "example.com:443")
}

func TestHY2URLOpaqueHy2(t *testing.T) {
	u, err := url.Parse("hy2://password@example.com:443/")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)

	// Opaque should strip the scheme prefix correctly for hy2://
	assert.Contains(t, hy2URL.Opaque(), "example.com:443")
	assert.NotContains(t, hy2URL.Opaque(), "hy2://")
}

func TestInsecureFalse(t *testing.T) {
	u, err := url.Parse("hysteria2://password@example.com:443/?insecure=false")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)
	assert.False(t, hy2URL.Config.Insecure)
}

func TestDefaultSNI(t *testing.T) {
	u, err := url.Parse("hysteria2://password@example.com:443/")
	assert.NoError(t, err)

	hy2URL, err := ParseHY2URL(u)
	assert.NoError(t, err)
	// SNI should default to the host when not specified
	assert.Equal(t, "example.com", hy2URL.Config.SNI)
}

func TestBothSchemesRegistered(t *testing.T) {
	// Verify both hysteria2 and hy2 schemes can be parsed
	urls := []string{
		"hysteria2://password@example.com:443",
		"hy2://password@example.com:443",
	}

	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		assert.NoError(t, err)

		parsed, err := ParseHY2URL(u)
		assert.NoError(t, err)
		assert.Equal(t, "example.com", parsed.Config.Address)
		assert.Equal(t, 443, parsed.Config.Port)
	}
}

func TestParseBandwidthValue(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
		wantErr  bool
	}{
		{"100 mbps", 100_000_000, false},
		{"50 Mbps", 50_000_000, false},
		{"10 kbps", 10_000, false},
		{"1000 bps", 1_000, false},
		{"1 gbps", 1_000_000_000, false},
		{"1", 1, false},
		{"", 0, true},                    // no number
		{"100xyz", 0, true},             // unknown unit
		{"100 m", 0, true},             // unknown unit (m alone is not mbps)
		{"100.5 mbps", 100_500_000, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseBandwidthValue(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}