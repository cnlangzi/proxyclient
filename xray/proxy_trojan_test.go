package xray

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

func TestProxyTrojan(t *testing.T) {
	if os.Getenv("GITHUB_REF") != "" {
		t.Skip("Skip test in GitHub Actions")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	trojanURL := "trojan://a38c9e28-9960-4e31-9f18-ed2495a756aa@vt-bana2-cn-11.ghpgwqswodgzv.com:40021?allowInsecure=0&sni=vt-bana2-cn-11.ghpgwqswodgzv.com&type=ws&host=vt-bana2-cn-11.ghpgwqswodgzv.com&path=%2Fdl_media#1%7C%F0%9F%87%AD%F0%9F%87%B010%20%7C%20%202.5MB/s"

	client, err := proxyclient.New(trojanURL, proxyclient.WithTransport(tr), proxyclient.WithTimeout(30*time.Second))
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
			t.Fatalf("Failed to make HTTPS request: %v", err)
		}
		defer resp.Body.Close() //nolint: errcheck

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK for %s, got %s", testURL, resp.Status)
		}

		buf, _ := io.ReadAll(resp.Body)
		fmt.Printf("response: %s\n", string(buf))
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
		fmt.Printf("response: %s\n", string(buf))
	})
}
