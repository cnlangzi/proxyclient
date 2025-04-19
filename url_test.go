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
