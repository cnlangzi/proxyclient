package ss

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/cnlangzi/proxyclient"
)

func init() {
	// Register the SS url parser
	proxyclient.RegisterParser("ss", func(u *url.URL) (proxyclient.URL, error) {
		return ParseSSURL(u)
	})
}

// Config holds Shadowsocks URL parameters
type Config struct {
	Server     string
	Port       int
	Method     string
	Password   string
	Plugin     string
	PluginOpts string
	Name       string
	raw        *url.URL `json:"-"`
}

type URL struct {
	Config *Config
}

func (v *URL) Raw() *url.URL {
	return v.Config.raw
}

func (v *URL) Opaque() string {
	return strings.TrimPrefix(v.Config.raw.String(), "ss://")
}

func (v *URL) Host() string {
	return v.Config.Server
}

func (v *URL) Port() string {
	return strconv.Itoa(v.Config.Port)
}

func (v *URL) Protocol() string {
	return "ss"
}

func (v *URL) User() string {
	return ""
}

func (v *URL) Password() string {
	return ""
}

// ParseSSURL parses a Shadowsocks URL
func ParseSSURL(u *url.URL) (*URL, error) {

	ssURL := u.String()

	// Remove the ss:// prefix
	encodedPart := strings.TrimPrefix(ssURL, "ss://")

	// Check if there's a tag/name part after #
	var name string
	if idx := strings.LastIndex(encodedPart, "#"); idx >= 0 {
		name, _ = url.PathUnescape(encodedPart[idx+1:])
		encodedPart = encodedPart[:idx]
	}

	// Check if the URL is using legacy format or SIP002
	var method, password, server, port string
	var plugin, pluginOpts string

	if strings.Contains(encodedPart, "@") {
		// SIP002 format
		idx := strings.Index(encodedPart, "@")
		userInfo := encodedPart[:idx]
		serverPart := encodedPart[idx+1:]

		// Decode user info which might be base64 encoded
		if !strings.Contains(userInfo, ":") {
			decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(userInfo)
			if err != nil {
				decoded, err = base64.StdEncoding.DecodeString(userInfo)
				if err != nil {
					return nil, fmt.Errorf("failed to decode user info: %w", err)
				}
			}
			userInfo = string(decoded)
		}

		parts := strings.SplitN(userInfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid user info format")
		}
		method = parts[0]
		password = parts[1]

		// Parse server address and plugin info
		serverURL, err := url.Parse("scheme://" + serverPart)
		if err != nil {
			return nil, fmt.Errorf("invalid server address: %w", err)
		}

		server = serverURL.Hostname()
		port = serverURL.Port()

		// Parse plugin parameters
		params := serverURL.Query()
		plugin = params.Get("plugin")
		if plugin != "" {
			pluginParts := strings.SplitN(plugin, ";", 2)
			if len(pluginParts) > 1 {
				plugin = pluginParts[0]
				pluginOpts = pluginParts[1]
			}
		}
	} else {
		// Legacy format - base64 encoded
		decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedPart)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(encodedPart)
			if err != nil {
				return nil, fmt.Errorf("failed to decode URL: %w", err)
			}
		}

		text := string(decoded)
		parts := strings.Split(text, "@")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid URL format")
		}

		methodPwd := strings.SplitN(parts[0], ":", 2)
		if len(methodPwd) != 2 {
			return nil, fmt.Errorf("invalid method:password format")
		}
		method = methodPwd[0]
		password = methodPwd[1]

		serverParts := strings.SplitN(parts[1], ":", 2)
		if len(serverParts) != 2 {
			return nil, fmt.Errorf("invalid server:port format")
		}
		server = serverParts[0]
		port = serverParts[1]
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	cfg := &Config{
		Server:     server,
		Port:       portInt,
		Method:     method,
		Password:   password,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
		Name:       name,

		raw: u,
	}

	return &URL{Config: cfg}, nil
}
