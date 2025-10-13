package ss

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

func TestProxySS(t *testing.T) {
	if os.Getenv("GITHUB_REF") != "" {
		t.Skip("Skip test in GitHub Actions")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Replace with a valid SS URL for testing
	proxyURL := "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206TURoaE1UZGpaREkwTWpJMlpXUmxOZz09OlpEUmxaV0ZoTjJJdE5ETmpOaTAwT1E9PQ==@hzhz1.sssyun.xyz:29527#1%7C%F0%9F%87%AD%F0%9F%87%B05%20%7C%20%201.7MB/s"

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
		defer resp.Body.Close() //nolint: errcheck

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
		defer resp.Body.Close() //nolint: errcheck

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK for %s, got %s", testURL, resp.Status)
		}

		buf, _ := io.ReadAll(resp.Body)
		fmt.Printf("HTTPS response: %s\n", string(buf))
	})
}
