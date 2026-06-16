package internal

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// TeleportConfig.getJwksUrl
// ---------------------------------------------------------------------------

func TestGetJwksUrl(t *testing.T) {
	tests := []struct {
		name     string
		config   TeleportConfig
		expected string
	}{
		{
			name:     "bare host gets https scheme and default path",
			config:   TeleportConfig{ProxyAddr: "teleport.example.com:8443"},
			expected: "https://teleport.example.com:8443/.well-known/jwks.json",
		},
		{
			name:     "trailing slash on proxy addr is trimmed",
			config:   TeleportConfig{ProxyAddr: "teleport.example.com:8443/"},
			expected: "https://teleport.example.com:8443/.well-known/jwks.json",
		},
		{
			name:     "http:// prefix is preserved (not doubled)",
			config:   TeleportConfig{ProxyAddr: "http://teleport.example.com"},
			expected: "http://teleport.example.com/.well-known/jwks.json",
		},
		{
			name:     "https:// prefix is preserved",
			config:   TeleportConfig{ProxyAddr: "https://teleport.example.com"},
			expected: "https://teleport.example.com/.well-known/jwks.json",
		},
		{
			name:     "OverrideJwksPath with leading slash",
			config:   TeleportConfig{ProxyAddr: "teleport.example.com", OverrideJwksPath: "/custom/jwks.json"},
			expected: "https://teleport.example.com/custom/jwks.json",
		},
		{
			name:     "OverrideJwksPath without leading slash gets one added",
			config:   TeleportConfig{ProxyAddr: "teleport.example.com", OverrideJwksPath: "custom/jwks.json"},
			expected: "https://teleport.example.com/custom/jwks.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.config.getJwksUrl()
			if got != tc.expected {
				t.Errorf("getJwksUrl() = %q, want %q", got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TeleportConfig.getTlsConfig
// ---------------------------------------------------------------------------

func TestGetTlsConfig(t *testing.T) {
	tests := []struct {
		name               string
		insecure           bool
		wantSkipVerify     bool
	}{
		{name: "secure: InsecureSkipVerify is false", insecure: false, wantSkipVerify: false},
		{name: "insecure: InsecureSkipVerify is true", insecure: true, wantSkipVerify: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := TeleportConfig{Insecure: tc.insecure}
			tlsCfg := cfg.getTlsConfig()
			if tlsCfg == nil {
				t.Fatal("getTlsConfig() returned nil")
			}
			if tlsCfg.InsecureSkipVerify != tc.wantSkipVerify {
				t.Errorf("InsecureSkipVerify = %v, want %v", tlsCfg.InsecureSkipVerify, tc.wantSkipVerify)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers for Validate tests
// ---------------------------------------------------------------------------

// writeTempCertKeyPair writes placeholder cert and key files in dir and
// returns their paths. (Content is irrelevant — Validate only stat()s them.)
func writeTempCertKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, []byte("cert"), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// validBaseConfig returns a *ProxyConfig that passes Validate with TLS files
// at the supplied paths.
func validBaseConfig(certFile, keyFile string) *ProxyConfig {
	return &ProxyConfig{
		Upstream: "http://backend.example.com",
		Server: ServerConfig{
			ListenHttp:  "0.0.0.0:8081",
			ListenHttps: "0.0.0.0:8444",
			CertFile:    certFile,
			KeyFile:     keyFile,
		},
		Teleport: TeleportConfig{
			ProxyAddr:   "teleport.example.com:8443",
			TokenHeader: "Teleport-Jwt-Assertion",
		},
	}
}

// ---------------------------------------------------------------------------
// ProxyConfig.Validate
// ---------------------------------------------------------------------------

func TestValidate(t *testing.T) {
	certFile, keyFile := writeTempCertKeyPair(t)

	tests := []struct {
		name      string
		mutate    func(*ProxyConfig)
		wantError bool
		// optional check after successful validation
		check func(t *testing.T, cfg *ProxyConfig)
	}{
		{
			name:      "valid config passes",
			mutate:    nil,
			wantError: false,
		},
		{
			name:      "empty upstream is rejected",
			mutate:    func(c *ProxyConfig) { c.Upstream = "" },
			wantError: true,
		},
		{
			name:      "upstream without scheme is rejected",
			mutate:    func(c *ProxyConfig) { c.Upstream = "backend.example.com" },
			wantError: true,
		},
		{
			name:      "upstream without host is rejected",
			mutate:    func(c *ProxyConfig) { c.Upstream = "http://" },
			wantError: true,
		},
		{
			name:      "empty token header is rejected",
			mutate:    func(c *ProxyConfig) { c.Teleport.TokenHeader = "" },
			wantError: true,
		},
		{
			name:      "empty proxy addr is rejected",
			mutate:    func(c *ProxyConfig) { c.Teleport.ProxyAddr = "" },
			wantError: true,
		},
		{
			name:      "insecure=true with http:// proxy addr is rejected",
			mutate:    func(c *ProxyConfig) { c.Teleport.Insecure = true; c.Teleport.ProxyAddr = "http://teleport.example.com" },
			wantError: true,
		},
		{
			name: "RequireTls=true clears ListenHttp",
			mutate: func(c *ProxyConfig) {
				c.Server.RequireTls = true
			},
			wantError: false,
			check: func(t *testing.T, cfg *ProxyConfig) {
				if cfg.Server.ListenHttp != "" {
					t.Errorf("ListenHttp = %q, want empty when RequireTls=true", cfg.Server.ListenHttp)
				}
			},
		},
		{
			name: "missing cert+key with RequireTls=false clears ListenHttps",
			mutate: func(c *ProxyConfig) {
				c.Server.CertFile = "/nonexistent/tls.crt"
				c.Server.KeyFile = "/nonexistent/tls.key"
			},
			wantError: false,
			check: func(t *testing.T, cfg *ProxyConfig) {
				if cfg.Server.ListenHttps != "" {
					t.Errorf("ListenHttps = %q, want empty when cert/key missing and RequireTls=false", cfg.Server.ListenHttps)
				}
			},
		},
		{
			name: "missing cert+key with RequireTls=true is rejected",
			mutate: func(c *ProxyConfig) {
				c.Server.RequireTls = true
				c.Server.CertFile = "/nonexistent/tls.crt"
				c.Server.KeyFile = "/nonexistent/tls.key"
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBaseConfig(certFile, keyFile)
			if tc.mutate != nil {
				tc.mutate(cfg)
			}

			err := cfg.Validate()
			if tc.wantError && err == nil {
				t.Error("Validate() returned nil, want error")
			}
			if !tc.wantError && err != nil {
				t.Errorf("Validate() returned unexpected error: %v", err)
			}
			if !tc.wantError && tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

// ensure getTlsConfig returns a *tls.Config (compile-time type check via assignment).
func TestGetTlsConfigNotNil(t *testing.T) {
	cfg := TeleportConfig{}
	if cfg.getTlsConfig() == nil {
		t.Error("getTlsConfig() returned nil")
	}
}
