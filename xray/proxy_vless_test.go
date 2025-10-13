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

func TestProxyVless(t *testing.T) {
	if os.Getenv("GITHUB_REF") != "" {
		t.Skip("Skip test in GitHub Actions")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	vlessURL := "vless://8a70d36b-dfb9-40cf-802e-70a82bc80ae2@104.26.14.85:8080?allowInsecure=0&sni=JP.8HVL7WyiPt.zuLaIR.oRg.&type=ws&host=JP.8HVL7WyiPt.zuLaIR.oRg.&path=/?ed=2048#14%7CUS_speednode_0053"

	client, err := proxyclient.New(vlessURL, proxyclient.WithTransport(tr), proxyclient.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	testURL := "ifconfig.io/ip"

	t.Run("http", func(t *testing.T) {

		req, err := http.NewRequest("GET", "http://"+testURL, nil)
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

		req, err := http.NewRequest("GET", "https://"+testURL, nil)
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
