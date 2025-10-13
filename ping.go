package proxyclient

import (
	"net"
	"time"
)

func Ping(host string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint: errcheck
	return true
}
