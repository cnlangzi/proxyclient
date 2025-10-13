package proxyclient

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxySocks(t *testing.T) {
	// Create a test server that we'll try to access through the proxy
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from target server") //nolint: errcheck
	}))
	defer targetServer.Close()

	t.Run("socks4", func(t *testing.T) {
		var proxyWasUsed bool

		// Create a simple SOCKS4 server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				proxyWasUsed = true
				go handleSocks4(conn, t)
			}
		}()
		defer listener.Close() //nolint: errcheck

		// Create proxy URL (socks4://127.0.0.1:port)
		proxyURL := fmt.Sprintf("socks4://%s", listener.Addr().String())

		// Create client using the SOCKS4 proxy
		client, err := New(proxyURL)
		require.NoError(t, err)

		// Make request to target server
		resp, err := client.Get(targetServer.URL)
		require.NoError(t, err, "Failed to make request through SOCKS4 proxy")
		defer resp.Body.Close() //nolint: errcheck

		// Verify proxy was used
		require.True(t, proxyWasUsed, "SOCKS4 proxy was not used")

		// Verify response
		require.Equal(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read response body")

		expectedBody := "Hello from target server"
		require.Equal(t, expectedBody, string(body), "Unexpected response body")
	})

	t.Run("socks5", func(t *testing.T) {
		var proxyWasUsed bool

		// Create a simple SOCKS5 server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				proxyWasUsed = true
				go handleSocks5(conn, t)
			}
		}()
		defer listener.Close() //nolint: errcheck

		// Create proxy URL (socks5://127.0.0.1:port)
		proxyURL := fmt.Sprintf("socks5://%s", listener.Addr().String())

		// Create client using the SOCKS5 proxy
		client, err := New(proxyURL)
		require.NoError(t, err)

		// Make request to target server
		resp, err := client.Get(targetServer.URL)
		require.NoError(t, err, "Failed to make request through SOCKS5 proxy")
		defer resp.Body.Close() //nolint: errcheck

		// Verify proxy was used
		require.True(t, proxyWasUsed, "SOCKS5 proxy was not used")

		// Verify response
		require.Equal(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read response body")

		expectedBody := "Hello from target server"
		require.Equal(t, expectedBody, string(body), "Unexpected response body")
	})
}
