package xray

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/cnlangzi/proxyclient"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func dialContext(ctx context.Context, instance *core.Instance, network, addr string) (net.Conn, error) {

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Convert port string to uint16
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Create network type based on the network parameter
	var netType xnet.Network
	switch network {
	case "tcp", "tcp4", "tcp6":
		netType = xnet.Network_TCP
	case "udp", "udp4", "udp6":
		netType = xnet.Network_UDP
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	// Create the destination
	dest := xnet.Destination{
		Network: netType,
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(portNum),
	}

	return proxyclient.WithRecover(func() (net.Conn, error) {
		return core.Dial(ctx, instance, dest)
	})

}
