package proxyclient

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

type ProxyFunc func(*url.URL, *Options) (http.RoundTripper, error)

var (
	supportProxies = make(map[string]ProxyFunc)
)

func RegisterProxy(proto string, f ProxyFunc) {
	supportProxies[proto] = f
}

func CreateTransport(o *Options) *http.Transport {
	return o.Transport.Clone()
}

func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

type JsonInt struct {
	v int
}

func (i *JsonInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.v)
}

func (i *JsonInt) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as an integer directly
	var valueInt int
	if err := json.Unmarshal(data, &valueInt); err == nil {
		*i = JsonInt{v: valueInt}
		return nil
	}

	// If that fails, try to unmarshal as a string
	var valueStr string
	if err := json.Unmarshal(data, &valueStr); err != nil {
		return fmt.Errorf("value must be an integer or a string representation of an integer: %w", err)
	}

	// Convert the string to an integer
	valueInt, err := strconv.Atoi(valueStr)
	if err != nil {
		return fmt.Errorf("failed to convert string to integer: %w", err)
	}

	*i = JsonInt{v: valueInt}
	return nil
}

// Add a getter method to retrieve the value
func (i JsonInt) Value() int {
	return i.v
}
