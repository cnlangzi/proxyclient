package xray

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	// Register the SSR url parser
	proxyclient.RegisterParser("ssr", func(u *url.URL) (proxyclient.URL, error) {
		return ParseSSRURL(u)
	})
}

// SSRConfig stores ShadowsocksR URL parameters
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

	raw *url.URL `json:"-"`
}

type SSRURL struct {
	cfg *SSRConfig
}

func (v *SSRURL) Raw() *url.URL {
	return v.cfg.raw
}

func (v *SSRURL) Title() string {
	return "ssr://" + v.Host() + ":" + v.Port()
}

func (v *SSRURL) Host() string {
	return v.cfg.Server
}

func (v *SSRURL) Port() string {
	return strconv.Itoa(v.cfg.Port)
}

func ParseSSRURL(u *url.URL) (*SSRURL, error) {

	ssrURL := u.String()
	// Remove ssr:// prefix
	ssrURL = strings.TrimPrefix(ssrURL, "ssr://")

	// Decode base64
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(ssrURL)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(ssrURL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode SSR URL: %w", err)
		}
	}

	text := string(decoded)

	// Separate main part and parameter part
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

	// Parse main part
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid SSR URL format")
	}

	serverPort, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Decode password
	password, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[5])
	if err != nil {
		// Try standard base64
		password, err = base64.StdEncoding.DecodeString(parts[5])
		if err != nil {
			return nil, fmt.Errorf("failed to decode password: %w", err)
		}
	}

	cfg := &SSRConfig{
		Server:   parts[0],
		Port:     serverPort,
		Protocol: parts[2],
		Method:   parts[3],
		Obfs:     parts[4],
		Password: string(password),

		raw: u,
	}

	// Parse parameter part
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
				// Try standard base64
				decodedValue, err = base64.StdEncoding.DecodeString(value)
				if err != nil {
					// Use original value
					decodedValue = []byte(value)
				}
			}

			switch key {
			case "obfsparam":
				cfg.ObfsParam = string(decodedValue)
			case "protoparam":
				cfg.ProtocolParam = string(decodedValue)
			case "remarks":
				cfg.Name = string(decodedValue)
			}
		}
	}

	return &SSRURL{
		cfg: cfg,
	}, nil
}
