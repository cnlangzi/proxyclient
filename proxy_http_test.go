package proxyclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProxyHTTP(t *testing.T) {
	// Create a test server that we'll try to access through the proxy
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from target server") //nolint: errcheck
	}))
	defer targetServer.Close()

	t.Run("http", func(t *testing.T) {
		var proxyWasUsed bool
		// Create a mock proxy server
		proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyWasUsed = true

			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}))
		defer proxyServer.Close()

		client, err := New(proxyServer.URL)
		require.NoError(t, err)

		// Make request to target server
		resp, err := client.Get(targetServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request through proxy: %v", err)
		}
		defer resp.Body.Close() //nolint: errcheck

		// Check if proxy was used
		if !proxyWasUsed {
			t.Error("Proxy was not used for the request")
		}

		// Verify response status
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.Status)
		}

		// Verify response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		expectedBody := "Hello from target server"
		if string(body) != expectedBody {
			t.Errorf("Expected body %q, got %q", expectedBody, string(body))
		}
	})

	t.Run("https", func(t *testing.T) {
		var proxyWasUsed bool

		proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyWasUsed = true
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}))

		defer proxyServer.Close()

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client, err := New(proxyServer.URL, WithTransport(tr), WithTimeout(5*time.Second))
		require.NoError(t, err)

		resp, err := client.Get(targetServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request through proxy: %v", err)
		}
		defer resp.Body.Close() //nolint: errcheck

		// Check if proxy was used
		if !proxyWasUsed {
			t.Error("Proxy was not used for the request")
		}

		// Verify response status
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.Status)
		}

		// Verify response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		expectedBody := "Hello from target server"
		if string(body) != expectedBody {
			t.Errorf("Expected body %q, got %q", expectedBody, string(body))
		}
	})

}
