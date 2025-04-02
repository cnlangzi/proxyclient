package proxyclient

import (
	"testing"
	"time"
)

func TestPing(t *testing.T) {
	// Test with a valid host and port
	host := "bing.com"
	port := "80"
	timeout := 5 * time.Second

	if !Ping(host, port, timeout) {
		t.Errorf("Expected to ping %s:%s successfully", host, port)
	}

	// Test with an invalid host
	host = "invalid.host"
	port = "80"

	if Ping(host, port, timeout) {
		t.Errorf("Expected to fail pinging %s:%s", host, port)
	}
}
