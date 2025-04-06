package ss

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
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
func handleConn(conn net.Conn, method, password, serverAddr string) {
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
	rc, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Printf("Failed to connect to server %s: %v\n", serverAddr, err)
		return
	}
	defer rc.Close()

	// Create the Shadowsocks method
	ssMethod, err := createMethod(method, password)
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
func startServer(port int, method, password, serverAddr string) (net.Listener, context.CancelFunc, error) {
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
				go handleConn(conn, method, password, serverAddr)
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

	cfg := su.cfg

	// Get a free port if none is provided
	if port < 1 {
		port, err = proxyclient.GetFreePort()
		if err != nil {
			return 0, err
		}
	}

	// Handle plugin if specified
	if cfg.Plugin != "" {
		return 0, fmt.Errorf("plugins are not supported in this implementation")
	}

	serverAddr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)

	// Start a SOCKS server that forwards to the Shadowsocks server
	listener, cancel, err := startServer(port, cfg.Method, cfg.Password, serverAddr)
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
