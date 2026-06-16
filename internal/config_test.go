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

// ---------------------------------------------------------------------------
// Validate: insecure=true with a non-http ProxyAddr triggers the warning log
// but must still pass validation (it is not an error).
// ---------------------------------------------------------------------------

func TestValidate_InsecureWarning(t *testing.T) {
	certFile, keyFile := writeTempCertKeyPair(t)
	cfg := validBaseConfig(certFile, keyFile)
	cfg.Teleport.Insecure = true
	// ProxyAddr does NOT start with "http", so the Insecure+http guard passes.
	// Validate should succeed but print the warning.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LoadConfig
// ---------------------------------------------------------------------------

// minimalYAML returns a valid config YAML string pointing at the given
// upstream and teleport proxy address.
func minimalYAML(upstream, teleportAddr string) string {
	return "upstream: \"" + upstream + "\"\n" +
		"teleport:\n" +
		"  proxyAddr: \"" + teleportAddr + "\"\n" +
		"server:\n" +
		"  listenHttp: \"127.0.0.1:0\"\n" +
		"  listenHttps: \"\"\n"
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte(minimalYAML("http://backend.example.com", "teleport.example.com:8443")), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("CONFIG_FILE", cfgFile)
	unsetEnv(t, "UPSTREAM", "TELEPORT_HOST")

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}
	if cfg.Upstream != "http://backend.example.com" {
		t.Errorf("Upstream = %q, want %q", cfg.Upstream, "http://backend.example.com")
	}
	if cfg.Teleport.ProxyAddr != "teleport.example.com:8443" {
		t.Errorf("ProxyAddr = %q, want %q", cfg.Teleport.ProxyAddr, "teleport.example.com:8443")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	unsetEnv(t, "CONFIG_FILE")
	// Switch to a temp dir with no config.yaml so the default file check fails.
	dir := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	t.Setenv("UPSTREAM", "http://env-backend.example.com")
	t.Setenv("TELEPORT_HOST", "env-teleport.example.com:8443")

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}
	if cfg.Upstream != "http://env-backend.example.com" {
		t.Errorf("Upstream = %q, want %q", cfg.Upstream, "http://env-backend.example.com")
	}
}

// ---------------------------------------------------------------------------
// loadConfigFrom
// ---------------------------------------------------------------------------

func TestLoadConfigFrom_NonexistentFile(t *testing.T) {
	_, err := loadConfigFrom("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("loadConfigFrom() expected error for nonexistent file, got nil")
	}
}

func TestLoadConfigFrom_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgFile, []byte(":::not valid yaml:::\n"), 0600); err != nil {
		t.Fatalf("write bad yaml: %v", err)
	}
	_, err := loadConfigFrom(cfgFile)
	if err == nil {
		t.Error("loadConfigFrom() expected error for malformed YAML, got nil")
	}
}

func TestLoadConfigFrom_DefaultFileFallback(t *testing.T) {
	// Change to a temp dir that has a valid config.yaml so the default
	// file fallback is exercised (configFile argument is empty string).
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, DEFAULT_CONFIG_FILE_NAME)
	if err := os.WriteFile(cfgFile, []byte(minimalYAML("http://default.example.com", "teleport.example.com:8443")), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	origWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	unsetEnv(t, "UPSTREAM", "TELEPORT_HOST")

	cfg, err := loadConfigFrom("") // empty → should pick up config.yaml in cwd
	if err != nil {
		t.Fatalf("loadConfigFrom(\"\") returned unexpected error: %v", err)
	}
	if cfg.Upstream != "http://default.example.com" {
		t.Errorf("Upstream = %q, want %q", cfg.Upstream, "http://default.example.com")
	}
}

func TestLoadConfigFrom_EnvFallback(t *testing.T) {
	// No config file; empty string + no default file → read from env.
	dir := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	t.Setenv("UPSTREAM", "http://fallback.example.com")
	t.Setenv("TELEPORT_HOST", "fallback-teleport.example.com:8443")

	cfg, err := loadConfigFrom("")
	if err != nil {
		t.Fatalf("loadConfigFrom(\"\") returned unexpected error: %v", err)
	}
	if cfg.Upstream != "http://fallback.example.com" {
		t.Errorf("Upstream = %q, want %q", cfg.Upstream, "http://fallback.example.com")
	}
}

// ---------------------------------------------------------------------------
// resolveConfigFile
// ---------------------------------------------------------------------------

func TestResolveConfigFile(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		env       map[string]string
		want      string
	}{
		{
			name: "flag takes precedence over env",
			args: []string{"--config-file", "/from/flag.yaml"},
			env:  map[string]string{"CONFIG_FILE": "/from/env.yaml"},
			want: "/from/flag.yaml",
		},
		{
			name: "env used when no flag",
			args: []string{},
			env:  map[string]string{"CONFIG_FILE": "/from/env.yaml"},
			want: "/from/env.yaml",
		},
		{
			name: "empty when neither set",
			args: []string{},
			env:  map[string]string{},
			want: "",
		},
		{
			name: "empty env value is ignored",
			args: []string{},
			env:  map[string]string{"CONFIG_FILE": ""},
			want: "",
		},
		{
			name: "config-file flag can appear anywhere in args",
			args: []string{"--config-file", "/explicit.yaml"},
			env:  map[string]string{},
			want: "/explicit.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookupEnv := func(key string) (string, bool) {
				v, ok := tc.env[key]
				return v, ok
			}
			got := resolveConfigFile(tc.args, lookupEnv)
			if got != tc.want {
				t.Errorf("resolveConfigFile() = %q, want %q", got, tc.want)
			}
		})
	}
}
