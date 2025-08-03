package ss

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cnlangzi/proxyclient"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	md "github.com/sagernet/sing/common/metadata"
)

var (
	mu      sync.Mutex
	proxies = make(map[string]*Server)
)

// Server represents a running Shadowsocks server
type Server struct {
	Method     string
	Password   string
	ServerAddr string
	Listener   net.Listener
	SocksPort  int
	Cancel     context.CancelFunc
}

// getServer looks up a running Shadowsocks server
func getServer(proxyURL string) *Server {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := proxies[proxyURL]; ok {
		return proxy
	}
	return nil
}

// setServer registers a running Shadowsocks server
func setServer(proxyURL string, server *Server) {
	mu.Lock()
	defer mu.Unlock()

	proxies[proxyURL] = server
}

// wrapConnectionWithPlugin applies plugin transformations to the connection
func wrapConnectionWithPlugin(conn net.Conn, cfg *Config) (net.Conn, error) {
	switch cfg.Plugin {
	case "v2ray-plugin":
		return wrapV2rayPlugin(conn, cfg)
	case "simple-obfs":
		return wrapSimpleObfs(conn, cfg)
	default:
		// Plugin is recognized but not implemented, just return original connection
		fmt.Printf("Plugin %s is not fully implemented, using plain connection\n", cfg.Plugin)
		return conn, nil
	}
}

// wrapV2rayPlugin wraps connection for v2ray-plugin (basic implementation)
func wrapV2rayPlugin(conn net.Conn, cfg *Config) (net.Conn, error) {
	// Parse plugin options
	opts := parsePluginOpts(cfg.PluginOpts)

	// If TLS is required, wrap with TLS
	if _, hasTLS := opts["tls"]; hasTLS {
		host := opts["host"]
		if host == "" {
			host = cfg.Server
		}

		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // For compatibility, should be configurable in production
		}

		tlsConn := tls.Client(conn, tlsConfig)
		err := tlsConn.Handshake()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

// wrapSimpleObfs wraps connection for simple-obfs (basic implementation)
func wrapSimpleObfs(conn net.Conn, cfg *Config) (net.Conn, error) {
	// Parse plugin options
	opts := parsePluginOpts(cfg.PluginOpts)

	// If HTTP obfuscation is enabled
	if opts["obfs"] == "http" {
		host := opts["obfs-host"]
		if host == "" {
			host = cfg.Server
		}

		// Send a simple HTTP request to disguise the connection
		httpReq := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: upgrade\r\n\r\n"
		_, err := conn.Write([]byte(httpReq))
		if err != nil {
			return nil, fmt.Errorf("failed to send obfs HTTP request: %w", err)
		}

		// Read and discard the HTTP response
		buffer := make([]byte, 1024)
		_, err = conn.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read obfs HTTP response: %w", err)
		}
	}

	return conn, nil
}

// parsePluginOpts parses plugin options string into a map
func parsePluginOpts(opts string) map[string]string {
	result := make(map[string]string)
	if opts == "" {
		return result
	}

	parts := strings.Split(opts, ";")
	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			result[kv[0]] = kv[1]
		} else {
			result[part] = "true"
		}
	}
	return result
}

// createMethod creates the appropriate Shadowsocks method based on the cipher type
func createMethod(method, password string) (shadowsocks.Method, error) {
	lowerMethod := strings.ToLower(method)

	if strings.HasPrefix(lowerMethod, "2022-") {
		// For 2022 methods using BLAKE3 KDF
		return shadowaead_2022.NewWithPassword(method, password, time.Now)
	} else {
		// For standard methods, we need to provide a dummy key since the password is used
		// The function signature requires (method string, key []byte, password string)
		// where key is ignored when password is provided
		return shadowaead.New(lowerMethod, nil, password)
	}
}

// handleConn handles a single client connection to the SOCKS server
// handleConn handles a single client connection to the SOCKS server
func handleConn(conn net.Conn, cfg *Config) {
	defer conn.Close()

	// Set a read deadline to prevent hanging
	conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // nolint:errcheck

	// Custom SOCKS5 handshake implementation with more error details
	// 1. Read the SOCKS version and number of methods
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil {
		// Only log EOF errors for non-verification connections
		if err != io.EOF {
			fmt.Printf("Failed to read SOCKS initial handshake: %v\n", err)
		}
		return
	}

	if n < 2 {
		fmt.Printf("SOCKS handshake too short: %d bytes\n", n)
		return
	}

	if buf[0] != 5 { // SOCKS5
		fmt.Printf("Unsupported SOCKS version: %d\n", buf[0])
		return
	}

	// 2. Send method selection message
	_, err = conn.Write([]byte{5, 0}) // SOCKS5, no authentication
	if err != nil {
		fmt.Printf("Failed to send SOCKS method selection: %v\n", err)
		return
	}

	// 3. Read the SOCKS request
	conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // nolint:errcheck
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("Failed to read SOCKS request: %v\n", err)
		return
	}

	if n < 7 {
		fmt.Printf("SOCKS request too short: %d bytes\n", n)
		return
	}

	if buf[0] != 5 { // SOCKS5
		fmt.Printf("Unsupported SOCKS version in request: %d\n", buf[0])
		return
	}

	if buf[1] != 1 { // CONNECT command
		fmt.Printf("Unsupported SOCKS command: %d\n", buf[1])
		return
	}

	var tgt []byte
	switch buf[3] { // ATYP
	case 1: // IPv4
		if n < 10 {
			fmt.Printf("SOCKS IPv4 request too short: %d bytes\n", n)
			return
		}
		tgt = buf[3:10]
	case 3: // Domain name
		addrLen := int(buf[4])
		if n < 5+addrLen+2 {
			fmt.Printf("SOCKS domain request too short: %d bytes\n", n)
			return
		}
		tgt = buf[3 : 5+addrLen+2]
	case 4: // IPv6
		if n < 22 {
			fmt.Printf("SOCKS IPv6 request too short: %d bytes\n", n)
			return
		}
		tgt = buf[3:22]
	default:
		fmt.Printf("Unsupported SOCKS address type: %d\n", buf[3])
		return
	}

	// 4. Send reply - success
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // SOCKS5, succeeded, IPv4, 0.0.0.0:0
	if err != nil {
		fmt.Printf("Failed to send SOCKS reply: %v\n", err)
		return
	}

	// Reset read deadline
	conn.SetReadDeadline(time.Time{}) // nolint:errcheck

	// Parse destination address from tgt
	var destHost string
	var destPort int

	switch tgt[0] {
	case 1: // IPv4
		destHost = net.IPv4(tgt[1], tgt[2], tgt[3], tgt[4]).String()
		destPort = int(tgt[5])<<8 | int(tgt[6])
	case 3: // Domain name
		addrLen := int(tgt[1])
		destHost = string(tgt[2 : 2+addrLen])
		destPort = int(tgt[2+addrLen])<<8 | int(tgt[3+addrLen])
	case 4: // IPv6
		destHost = net.IP(tgt[1:17]).String()
		destPort = int(tgt[17])<<8 | int(tgt[18])
	}

	fmt.Printf("SOCKS handshake successful, target: %s:%d\n", destHost, destPort)

	// Connect to the Shadowsocks server
	serverAddr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))

	// Apply timeout from config for server connection
	var rc net.Conn
	if cfg.Timeout > 0 {
		timeout := time.Duration(cfg.Timeout) * time.Second
		rc, err = net.DialTimeout("tcp", serverAddr, timeout)
	} else {
		rc, err = net.Dial("tcp", serverAddr)
	}
	if err != nil {
		fmt.Printf("Failed to connect to server %s: %v\n", serverAddr, err)
		return
	}
	defer rc.Close()

	// Apply plugin wrapper if configured
	if cfg.Plugin != "" {
		rc, err = wrapConnectionWithPlugin(rc, cfg)
		if err != nil {
			fmt.Printf("Failed to apply plugin %s: %v\n", cfg.Plugin, err)
			return
		}
	}

	// Create the Shadowsocks method
	ssMethod, err := createMethod(cfg.Method, cfg.Password)
	if err != nil {
		fmt.Printf("Failed to create cipher: %v\n", err)
		return
	}

	// Create destination address
	destination := md.ParseSocksaddr(fmt.Sprintf("%s:%d", destHost, destPort))

	// Create a connection to the server
	ssConn, err := ssMethod.DialConn(rc, destination)
	if err != nil {
		fmt.Printf("Failed to create SS connection: %v\n", err)
		return
	}

	fmt.Printf("Starting data transfer for %s:%d\n", destHost, destPort)

	// Handle bidirectional copy with better error reporting
	done := make(chan error, 2)

	// Client to server
	go func() {
		_, err := io.Copy(ssConn, conn)
		done <- err
		ssConn.Close()
		fmt.Printf("Client to server copy finished for %s:%d, err: %v\n", destHost, destPort, err)
	}()

	// Server to client
	_, err = io.Copy(conn, ssConn)
	fmt.Printf("Server to client copy finished for %s:%d, err: %v\n", destHost, destPort, err)

	// Wait for the other goroutine to finish
	clientErr := <-done
	if clientErr != nil && clientErr != io.EOF {
		fmt.Printf("Client to server error: %v\n", clientErr)
	}

	fmt.Printf("Connection to %s:%d closed\n", destHost, destPort)
}

// startServer starts a SOCKS server that forwards to a Shadowsocks server
func startServer(port int, cfg *Config) (net.Listener, context.CancelFunc, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %d: %w", port, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						fmt.Printf("Failed to accept connection: %v\n", err)
						continue
					}
				}
				go handleConn(conn, cfg)
			}
		}
	}()

	return listener, cancel, nil
}

// StartSS starts a Shadowsocks client and returns local SOCKS port
func StartSS(u *url.URL, port int) (int, error) {

	ssURL := u.String()
	// Check if already running
	server := getServer(ssURL)
	if server != nil {
		return server.SocksPort, nil
	}

	// Parse SS URL
	su, err := ParseSSURL(u)
	if err != nil {
		return 0, err
	}

	cfg := su.Config

	// Get a free port if none is provided
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return 0, err
		}
	}

	// Handle plugin if specified
	if cfg.Plugin != "" {
		fmt.Printf("Plugin detected: %s with options: %s\n", cfg.Plugin, cfg.PluginOpts)

		switch cfg.Plugin {
		case "v2ray-plugin":
			fmt.Printf("Using v2ray-plugin for enhanced obfuscation\n")
			// v2ray-plugin 通过 WebSocket 或 TLS 来包装连接
			// 在实际实现中，这需要对连接进行相应的包装
		case "simple-obfs":
			fmt.Printf("Using simple-obfs for traffic obfuscation\n")
			// simple-obfs 通过 HTTP 请求来伪装流量
			// 在实际实现中，这需要发送虚假的 HTTP 请求头
		default:
			fmt.Printf("Warning: Plugin '%s' is recognized but not fully implemented\n", cfg.Plugin)
		}
	}

	serverAddr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)

	// Start a SOCKS server that forwards to the Shadowsocks server
	listener, cancel, err := startServer(port, cfg)
	if err != nil {
		return 0, err
	}

	// Add a small delay to ensure the server is ready
	time.Sleep(100 * time.Millisecond)

	// Store the running server
	setServer(ssURL, &Server{
		Method:     cfg.Method,
		Password:   cfg.Password,
		ServerAddr: serverAddr,
		Listener:   listener,
		SocksPort:  port,
		Cancel:     cancel,
	})

	return port, nil
}

// Close shuts down a running Shadowsocks client
func Close(proxyURL string) {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := proxies[proxyURL]; ok {
		if proxy.Cancel != nil {
			proxy.Cancel()
		}
		if proxy.Listener != nil {
			proxy.Listener.Close()
		}
		delete(proxies, proxyURL)
	}
}
