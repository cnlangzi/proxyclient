# ProxyClient
Enhanced HTTP Client with Multi-Proxy Support for Go

`ProxyClient` is a Go package that extends the standard `http.Client` to seamlessly support multiple proxy protocols, including **HTTP/HTTPS, SOCKS4, SOCKS5, SSL, V2Ray, SSR/SS, and MTProto**. It provides a unified interface for developers to interact with diverse proxy types without manual low-level configurations.

[![Tests](https://github.com/cnlangzi/proxyclient/actions/workflows/tests.yml/badge.svg)](https://github.com/cnlangzi/proxyclient/actions/workflows/tests.yml)
[![Codecov](https://codecov.io/gh/cnlangzi/proxyclient/branch/main/graph/badge.svg)](https://codecov.io/gh/cnlangzi/proxyclient)
[![Go Report Card](https://goreportcard.com/badge/github.com/cnlangzi/proxyclient)](https://goreportcard.com/report/github.com/cnlangzi/proxyclient)
[![Go Reference](https://pkg.go.dev/badge/github.com/cnlangzi/proxyclient.svg)](https://pkg.go.dev/github.com/cnlangzi/proxyclient)
[![GitHub Release](https://img.shields.io/github/v/release/cnlangzi/proxyclient)](https://github.com/cnlangzi/proxyclient/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-blue.svg)](https://github.com/cnlangzi/proxyclient/compare)


### **Features**  
• **Multi-Protocol Support**:  
  • **HTTP/HTTPS Proxy**: Direct and authenticated connections.  
  • **SOCKS4/SOCKS5**: Full support for SOCKS protocols (IPv4/IPv6).  
  • **SSL/TLS Tunneling**: Secure proxy tunneling for encrypted traffic.  
  • **V2Ray/SSR/SS**: Integration with popular proxy tools (Shadowsocks, V2Ray core).  
  • **MTProto**: Native support for Telegram’s MTProto protocol.  

• **Simplified API**: Create a proxy-enabled client with a single function call.  
• **Authentication**: Built-in handling for username/password, encryption keys, and token-based auth.  
• **Compatibility**: Fully compatible with Go’s standard `http.Client` methods (`Get`, `Post`, etc.).  



### **Quick Start**  
#### **Installation**  
```bash
go get github.com/cnlangzi/proxyclient
```

#### **Usage Example**  
```go
package main

import (
    "fmt"
    "github.com/cnlangzi/proxyclient"
    // import v5 vmess/vless
    _ "github.com/cnlangzi/proxyclient/v2ray"
)

func main() {
    // Create a client with SOCKS5 proxy
    client, err := proxyclient.New("socks5://user:pass@127.0.0.1:1080")
    
    if err != nil {
        panic(err)
    }

    // Use like a standard http.Client
    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("Response status:", resp.Status)
}
```

---

### **Supported Proxy Types**  
| Protocol  | Example Config                                            |  
|-----------|-----------------------------------------------------------| 
| HTTP      | `http://user:pass@127.0.0.1:8080`                         |  
| HTTPs     | `https://user:pass@127.0.0.1:8080`                        |  
| SOCKS4    | `socks4://user:pass@127.0.0.1:1080`                       |  
| SOCKS5    | `socks5://user:pass@127.0.0.1:1080`                       | 
| ssh       | `ssh://user:pass@127.0.0.1:2222`                          |   
| vmess(v5) | `vmess://eyJ2IjogIjIiLCAicHMiOiAiXHU1Yz...`               |  
| vless(v5) | `vless://8a...ae2@104.26.14.85:8080?allowInsecure=0&sni=` |
| SS        | `ss://user:pass@127.0.0.1:8080`                           |  
| SSR       | `ssr://user:pass@127.0.0.1:8080`                          |  
| MTProto   | `mtproto://user:pass@127.0.0.1:8080`                      |  

---


### **Why Use `proxyclient`?**  
• **Unified Interface**: Simplify code for multi-proxy environments.  
• **Extensible**: Easily add new proxy protocols via modular design.  

--- 

Contributions welcome! 🚀