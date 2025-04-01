package v2ray

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cnlangzi/proxyclient"
)

func TestProxyVmess(t *testing.T) {
	if os.Getenv("GITHUB_REF") != "" {
		t.Skip("Skip test in GitHub Actions")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	proxyURL := "vmess://eyJ2IjogIjIiLCAicHMiOiAiXHU1YzcxXHU0ZTFjXHU3NzAxXHU5NzUyXHU1YzliXHU1ZTAyIFx1ODA1NFx1OTAxYSIsICJhZGQiOiAidjQwLmhlZHVpYW4ubGluayIsICJwb3J0IjogIjMwODQwIiwgInR5cGUiOiAibm9uZSIsICJpZCI6ICJjYmIzZjg3Ny1kMWZiLTM0NGMtODdhOS1kMTUzYmZmZDU0ODQiLCAiYWlkIjogIjAiLCAibmV0IjogIndzIiwgInBhdGgiOiAiL2luZGV4IiwgImhvc3QiOiAiYXBpMTAwLWNvcmUtcXVpYy1sZi5hbWVtdi5jb20iLCAidGxzIjogIiJ9"

	client, err := proxyclient.New(proxyURL, proxyclient.WithTransport(tr), proxyclient.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	t.Run("http", func(t *testing.T) {
		testURL := "http://ifconfig.io/ip"
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make HTTP request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK for %s, got %s", testURL, resp.Status)
		}

		buf, _ := io.ReadAll(resp.Body)
		fmt.Printf("HTTP response: %s\n", string(buf))
	})

	t.Run("https", func(t *testing.T) {
		testURL := "https://ifconfig.io/ip"
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK for %s, got %s", testURL, resp.Status)
		}

		buf, _ := io.ReadAll(resp.Body)
		fmt.Printf("HTTPS response: %s\n", string(buf))
	})
}
