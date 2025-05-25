package proxyclient

import "testing"

func TestIsDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Standard domain names
		{name: "Simple domain", domain: "example.com", expected: true},
		{name: "Subdomain", domain: "sub.example.com", expected: true},
		{name: "Multi-level domain", domain: "a.b.c.example.com", expected: true},
		{name: "www domain", domain: "www.example.com", expected: true},

		// Domains with special characters
		{name: "Domain with hyphen", domain: "my-domain.com", expected: true},
		{name: "Domain with underscore", domain: "my_domain.com", expected: true},
		{name: "Domain with hyphen and underscore", domain: "my-domain_name.com", expected: true},

		// Non-standard TLDs
		{name: "Single character TLD", domain: "example.x", expected: true},
		{name: "Numeric TLD", domain: "example.123", expected: true},
		{name: "Hyphenated TLD", domain: "example.my-domain", expected: true},
		{name: "TLD with underscore", domain: "example.my_tld", expected: true},

		// Multi-level TLDs
		{name: "Double TLD", domain: "example.co.uk", expected: true},
		{name: "Triple TLD", domain: "example.co.jp", expected: true},

		// Internationalized domain names (IDN)
		{name: "Chinese domain", domain: "例子.中国", expected: true},
		{name: "Japanese domain", domain: "テスト.jp", expected: true},
		{name: "Russian domain", domain: "пример.рф", expected: true},
		{name: "Arabic domain", domain: "مثال.مصر", expected: true},
		{name: "Punycode domain", domain: "xn--fsq.xn--fiqs8s", expected: true},

		// Edge cases
		{name: "Domain with numbers", domain: "123.example.com", expected: true},
		{name: "Domain with number start", domain: "123example.com", expected: true},
		{name: "Maximum length label (63 chars)", domain: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com", expected: true},

		// Invalid domains
		{name: "Empty string", domain: "", expected: false},
		{name: "Just TLD", domain: ".com", expected: false},
		{name: "Invalid character !", domain: "example!.com", expected: false},
		{name: "Invalid character @", domain: "exa@mple.com", expected: false},
		{name: "Too long label (64 chars)", domain: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.com", expected: false},
		{name: "Missing TLD", domain: "example", expected: false},
		{name: "Double dot", domain: "example..com", expected: false},
		{name: "Start with dot", domain: ".example.com", expected: false},
		{name: "End with dot", domain: "example.com.", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("IsDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

// Test specifically focusing on IDN domains
func TestIsDomain_IDN(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{name: "Chinese domain and TLD", domain: "例子.中国", expected: true},
		{name: "Chinese subdomain", domain: "子域名.例子.中国", expected: true},
		{name: "Mixed ASCII and Chinese", domain: "test.例子.com", expected: true},
		{name: "Cyrillic domain", domain: "тест.рф", expected: true},
		{name: "Hebrew domain", domain: "בדיקה.il", expected: true},
		{name: "Thai domain", domain: "ทดสอบ.th", expected: true},
		{name: "Korean domain", domain: "테스트.kr", expected: true},
		{name: "Greek domain", domain: "δοκιμή.gr", expected: true},
		{name: "Arabic domain and numbers", domain: "اختبار123.مصر", expected: true},

		// Punycode equivalents
		{name: "Punycode for Chinese domain", domain: "xn--fsq.xn--fiqs8s", expected: true},   // 例子.中国
		{name: "Punycode for Cyrillic domain", domain: "xn--e1aybc.xn--p1ai", expected: true}, // тест.рф

		// Invalid IDN domains
		{name: "Invalid IDN character sequence", domain: "\u0080test.com", expected: false},
		{name: "Invalid mixed direction text", domain: "اختبارtest.com", expected: false}, // Might be caught by IDNA normalization
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("IsDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestIsIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Valid IPv4 addresses
		{name: "Valid IPv4 - localhost", ip: "127.0.0.1", expected: true},
		{name: "Valid IPv4 - private", ip: "192.168.1.1", expected: true},
		{name: "Valid IPv4 - public", ip: "8.8.8.8", expected: true},
		{name: "Valid IPv4 - zero", ip: "0.0.0.0", expected: true},
		{name: "Valid IPv4 - broadcast", ip: "255.255.255.255", expected: true},
		{name: "Valid IPv4 - class A", ip: "10.0.0.1", expected: true},
		{name: "Valid IPv4 - class B", ip: "172.16.0.1", expected: true},
		{name: "Valid IPv4 - class C", ip: "203.0.113.1", expected: true},

		// Valid IPv6 addresses
		{name: "Valid IPv6 - loopback", ip: "::1", expected: true},
		{name: "Valid IPv6 - full", ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expected: true},
		{name: "Valid IPv6 - compressed", ip: "2001:db8:85a3::8a2e:370:7334", expected: true},
		{name: "Valid IPv6 - all zeros", ip: "::", expected: true},
		{name: "Valid IPv6 - link local", ip: "fe80::1", expected: true},
		{name: "Valid IPv6 - multicast", ip: "ff02::1", expected: true},
		// don't support IPv6 with zone
		{name: "Valid IPv6 - with zone", ip: "fe80::1%lo0", expected: false},
		{name: "Valid IPv6 - mapped IPv4", ip: "::ffff:192.0.2.1", expected: true},
		{name: "Valid IPv6 - embedded IPv4", ip: "2001:db8::192.0.2.1", expected: true},

		// IPv6 with brackets (should be stripped)
		{name: "IPv6 with brackets", ip: "[2001:db8::1]", expected: true},
		{name: "IPv6 loopback with brackets", ip: "[::1]", expected: true},
		// don't support IPv6 with zone
		{name: "IPv6 with zone and brackets", ip: "[fe80::1%eth0]", expected: false},

		// Invalid IP addresses
		{name: "Invalid IPv4 - too many octets", ip: "192.168.1.1.1", expected: false},
		{name: "Invalid IPv4 - too few octets", ip: "192.168.1", expected: false},
		{name: "Invalid IPv4 - octet too large", ip: "256.1.1.1", expected: false},
		{name: "Invalid IPv4 - negative octet", ip: "-1.1.1.1", expected: false},
		{name: "Invalid IPv4 - leading zeros", ip: "192.168.001.1", expected: false},
		{name: "Invalid IPv4 - letters", ip: "192.168.a.1", expected: false},
		{name: "Invalid IPv4 - empty octet", ip: "192..1.1", expected: false},

		{name: "Invalid IPv6 - too many groups", ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra", expected: false},
		{name: "Invalid IPv6 - invalid hex", ip: "2001:0db8:85a3:gggg:0000:8a2e:0370:7334", expected: false},
		{name: "Invalid IPv6 - too many double colons", ip: "2001::85a3::7334", expected: false},
		{name: "Invalid IPv6 - group too long", ip: "2001:0db8:85a30:0000:0000:8a2e:0370:7334", expected: false},

		// Edge cases
		{name: "Empty string", ip: "", expected: false},
		{name: "Just dots", ip: "...", expected: false},
		{name: "Just colons", ip: ":::", expected: false},
		{name: "Whitespace", ip: " ", expected: false},
		{name: "IPv4 with leading space", ip: " 192.168.1.1", expected: false},
		{name: "IPv4 with trailing space", ip: "192.168.1.1 ", expected: false},
		{name: "IPv6 with space", ip: "2001:db8:: 1", expected: false},
		{name: "Domain name", ip: "example.com", expected: false},
		{name: "localhost string", ip: "localhost", expected: false},
		{name: "Mixed format", ip: "192.168.1.1:2001:db8::1", expected: false},

		// Malformed brackets
		{name: "IPv4 with brackets", ip: "[192.168.1.1]", expected: false}, // mustIPv6=true but it's IPv4
		{name: "Unmatched opening bracket", ip: "[2001:db8::1", expected: false},
		{name: "Unmatched closing bracket", ip: "2001:db8::1]", expected: false},
		{name: "Empty brackets", ip: "[]", expected: false},
		{name: "Nested brackets", ip: "[[2001:db8::1]]", expected: false},
		{name: "IPv4 in brackets should fail", ip: "[127.0.0.1]", expected: false}, // mustIPv6=true but it's IPv4
		{name: "Invalid IPv4 in brackets", ip: "[192.168.1.999]", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestIsIP_EdgeCases tests additional edge cases and boundary conditions
func TestIsIP_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// IPv6 zone identifiers
		{name: "IPv6 with numeric zone", ip: "fe80::1%1", expected: false},
		{name: "IPv6 with interface name", ip: "fe80::1%eth0", expected: false},
		{name: "IPv6 with complex zone", ip: "fe80::1%en0.100", expected: false},

		// IPv6 special addresses
		{name: "IPv6 unspecified", ip: "::", expected: true},
		{name: "IPv6 documentation", ip: "2001:db8::", expected: true},
		{name: "IPv6 6to4", ip: "2002::", expected: true},
		{name: "IPv6 teredo", ip: "2001::", expected: true},

		// Very specific invalid cases
		{name: "IPv4 with port", ip: "192.168.1.1:8080", expected: false},
		{name: "IPv6 with port in brackets", ip: "[2001:db8::1]:8080", expected: false},
		{name: "URL-like format", ip: "http://192.168.1.1", expected: false},
		{name: "IPv4 CIDR notation", ip: "192.168.1.0/24", expected: false},
		{name: "IPv6 CIDR notation", ip: "2001:db8::/32", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
