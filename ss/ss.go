package ss

import (
	"context"
	"encoding/base64"
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
	M "github.com/sagernet/sing/common/metadata"
)

// SSConfig holds Shadowsocks URL parameters
type SSConfig struct {
	Server     string
	Port       int
	Method     string
	Password   string
	Plugin     string
	PluginOpts string
	Name       string
}

var (
	mu      sync.Mutex
	proxies = make(map[string]*SSServer)
)

// SSServer represents a running Shadowsocks server
type SSServer struct {
	Method     string
	Password   string
	ServerAddr string
	Listener   net.Listener
	SocksPort  int
	Cancel     context.CancelFunc
}

// ParseSS parses a Shadowsocks URL
func ParseSS(ssURL string) (*SSConfig, error) {
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

	return &SSConfig{
		Server:     server,
		Port:       portInt,
		Method:     method,
		Password:   password,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
		Name:       name,
	}, nil
}

// getServer looks up a running Shadowsocks server
func getServer(proxyURL string) *SSServer {
	mu.Lock()
	defer mu.Unlock()

	if proxy, ok := proxies[proxyURL]; ok {
		return proxy
	}
	return nil
}

// setServer registers a running Shadowsocks server
func setServer(proxyURL string, server *SSServer) {
	mu.Lock()
	defer mu.Unlock()

	proxies[proxyURL] = server
}

// createShadowsocksMethod creates the appropriate Shadowsocks method based on the cipher type
func createShadowsocksMethod(method, password string) (shadowsocks.Method, error) {
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

// handleShadowsocksConnection handles a single client connection to the SOCKS server
func handleShadowsocksConnection(conn net.Conn, method, password, serverAddr string) {
	defer conn.Close()

	// Set a read deadline to prevent hanging
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Check if this is likely a verification connection
	remoteAddr := conn.RemoteAddr().String()
	isLocalConnection := strings.HasPrefix(remoteAddr, "127.0.0.1:") ||
		strings.HasPrefix(remoteAddr, "[::1]:")

	// Read the first few bytes with a very short timeout for verification connections
	if isLocalConnection {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}

	// Add more detailed logging for the SOCKS handshake
	fmt.Printf("New connection from %s, starting SOCKS handshake\n", remoteAddr)

	// Custom SOCKS5 handshake implementation with more error details
	// 1. Read the SOCKS version and number of methods
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil {
		// Only log EOF errors for non-verification connections
		if err != io.EOF || !isLocalConnection {
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
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
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
	conn.SetReadDeadline(time.Time{})

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
	rc, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Printf("Failed to connect to server %s: %v\n", serverAddr, err)
		return
	}
	defer rc.Close()

	// Create the Shadowsocks method
	ssMethod, err := createShadowsocksMethod(method, password)
	if err != nil {
		fmt.Printf("Failed to create cipher: %v\n", err)
		return
	}

	// Create destination address
	destination := M.ParseSocksaddr(fmt.Sprintf("%s:%d", destHost, destPort))

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

// startShadowsocksServer starts a SOCKS server that forwards to a Shadowsocks server
func startShadowsocksServer(port int, method, password, serverAddr string) (net.Listener, context.CancelFunc, error) {
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
				go handleShadowsocksConnection(conn, method, password, serverAddr)
			}
		}
	}()

	return listener, cancel, nil
}

// StartSS starts a Shadowsocks client and returns local SOCKS port
func StartSS(ssURL string, port int) (int, error) {
	// Check if already running
	server := getServer(ssURL)
	if server != nil {
		return server.SocksPort, nil
	}

	// Parse SS URL
	ss, err := ParseSS(ssURL)
	if err != nil {
		return 0, err
	}

	// Get a free port if none is provided
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return 0, err
		}
	}

	// Handle plugin if specified
	if ss.Plugin != "" {
		return 0, fmt.Errorf("plugins are not supported in this implementation")
	}

	serverAddr := fmt.Sprintf("%s:%d", ss.Server, ss.Port)

	// Start a SOCKS server that forwards to the Shadowsocks server
	listener, cancel, err := startShadowsocksServer(port, ss.Method, ss.Password, serverAddr)
	if err != nil {
		return 0, err
	}

	// Add a small delay to ensure the server is ready
	time.Sleep(100 * time.Millisecond)

	// Store the running server
	setServer(ssURL, &SSServer{
		Method:     ss.Method,
		Password:   ss.Password,
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
