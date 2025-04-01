package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cnlangzi/proxyclient/v2ray"
	core "github.com/v2fly/v2ray-core/v5"
)

var (
	proxy string
	port  int
)

func main() {
	flag.StringVar(&proxy, "proxy", "", "vmess/vless url")
	flag.IntVar(&port, "port", 10800, "socks5 port")
	flag.Parse()

	var err error
	var inst *core.Instance
	var actualPort int

	if strings.HasPrefix(proxy, "vmess://") {
		inst, actualPort, err = v2ray.StartVmess(proxy, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start VMess proxy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VMess proxy started on socks5://127.0.0.1:%d\n", actualPort)
	} else if strings.HasPrefix(proxy, "vless://") {
		inst, actualPort, err = v2ray.StartVless(proxy, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start VLESS proxy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VLESS proxy started on socks5://127.0.0.1:%d\n", actualPort)
	} else {
		fmt.Fprintf(os.Stderr, "Error: Unknown proxy type. URL must start with vmess:// or vless://\n")
		os.Exit(1)
	}

	// 设置信号处理
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Proxy is running. Press Ctrl+C to stop.")

	// 等待信号
	<-osSignals

	fmt.Println("Shutting down proxy...")

	// 关闭V2Ray实例
	if inst != nil {
		err := inst.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down: %v\n", err)
		}
	}

	fmt.Println("Proxy has been stopped.")
}
