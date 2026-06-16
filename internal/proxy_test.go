package internal

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ---------------------------------------------------------------------------
// test scaffolding
// ---------------------------------------------------------------------------

// newTestProxy creates a Proxy with an injected jwk.Set so tests
// do not need a live JWKS server.
func newTestProxy(t *testing.T, config *ProxyConfig, pubSet jwk.Set) *Proxy {
	t.Helper()
	return &Proxy{
		Config: config,
		Logger: newDiscardLogger(),
		keySet: pubSet,
	}
}

// runMiddleware drives a single request through authenticationMiddleware.
// It returns the recorded response and the request headers as seen by the stub handler.
// If the middleware calls next, the stub records the request headers it received.
func runMiddleware(t *testing.T, proxy *Proxy, req *http.Request) (*httptest.ResponseRecorder, http.Header) {
	t.Helper()

	var capturedHeaders http.Header

	e := echo.New()
	handler := proxy.authenticationMiddleware(func(c *echo.Context) error {
		capturedHeaders = c.Request().Header.Clone()
		return c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := handler(c); err != nil {
		e.HTTPErrorHandler(c, err)
	}

	return rec, capturedHeaders
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware_NoToken(t *testing.T) {
	_, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	proxy := newTestProxy(t, cfg, pubSet)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_GarbageToken(t *testing.T) {
	_, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	proxy := newTestProxy(t, cfg, pubSet)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", "not.a.valid.jwt")
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_UnknownKey(t *testing.T) {
	_, pubSet := generateKeyPair(t)   // server trusts this set
	otherKey, _ := generateKeyPair(t) // token signed with a different key

	cfg := minimalProxyConfig("http://backend")
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, otherKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_DisallowedUser(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AccessControl = AccessControl{AllowedUsers: []string{"alice"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "mallory"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_DisallowedRole(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AccessControl = AccessControl{AllowedRoles: []string{"admin"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice", roles: []string{"viewer"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

func TestAuthMiddleware_ValidToken(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAuthMiddleware_ValidToken_AllowedUser(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AccessControl = AccessControl{AllowedUsers: []string{"alice"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAuthMiddleware_ValidToken_AllowedRole(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AccessControl = AccessControl{AllowedRoles: []string{"admin"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice", roles: []string{"admin", "viewer"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	rec, _ := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Header stripping (security-critical)
// ---------------------------------------------------------------------------

// Spoofed headers that match enabled header features must always be stripped,
// even if an attacker sends them on the incoming request.
func TestAuthMiddleware_SpooferCannotInjectUsernameHeader(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.UsernameHeader = "X-Forwarded-User"
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	req.Header.Set("X-Forwarded-User", "mallory") // attacker-supplied

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if upstreamHeaders.Get("X-Forwarded-User") != "alice" {
		t.Errorf("X-Forwarded-User = %q, want %q (spoofed value must be overwritten with token claim)",
			upstreamHeaders.Get("X-Forwarded-User"), "alice")
	}
}

func TestAuthMiddleware_SpooferCannotInjectAuthorizationHeader(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	// PassAsBearer is NOT set — Authorization must be stripped regardless.
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	req.Header.Set("Authorization", "Bearer evil-token")

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if upstreamHeaders.Get("Authorization") != "" {
		t.Errorf("Authorization header should be stripped, got %q", upstreamHeaders.Get("Authorization"))
	}
}

// ---------------------------------------------------------------------------
// PassToken
// ---------------------------------------------------------------------------

func TestAuthMiddleware_PassToken_False(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.PassToken = false
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if upstreamHeaders.Get("Teleport-Jwt-Assertion") != "" {
		t.Error("Teleport token header should be stripped when PassToken=false")
	}
}

func TestAuthMiddleware_PassToken_True(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.PassToken = true
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if upstreamHeaders.Get("Teleport-Jwt-Assertion") == "" {
		t.Error("Teleport token header should be forwarded when PassToken=true")
	}
}

// ---------------------------------------------------------------------------
// PassAsBearer
// ---------------------------------------------------------------------------

func TestAuthMiddleware_PassAsBearer(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.PassToken = true  // keep the token so it can be used as bearer
	cfg.Token.PassAsBearer = true
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	auth := upstreamHeaders.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer prefix", auth)
	}
}

func TestAuthMiddleware_PassAsBearer_False(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.PassAsBearer = false
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if upstreamHeaders.Get("Authorization") != "" {
		t.Errorf("Authorization should be empty when PassAsBearer=false, got %q", upstreamHeaders.Get("Authorization"))
	}
}

// ---------------------------------------------------------------------------
// PassTokenAsHeader
// ---------------------------------------------------------------------------

func TestAuthMiddleware_PassTokenAsHeader(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.PassToken = true
	cfg.Token.PassTokenAsHeader = "X-Custom-Token"
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	custom := upstreamHeaders.Get("X-Custom-Token")
	if !strings.HasPrefix(custom, "Bearer ") {
		t.Errorf("X-Custom-Token = %q, want Bearer prefix", custom)
	}
}

// ---------------------------------------------------------------------------
// UsernameHeader
// ---------------------------------------------------------------------------

func TestAuthMiddleware_UsernameHeader(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.UsernameHeader = "X-Remote-User"
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{username: "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if got := upstreamHeaders.Get("X-Remote-User"); got != "alice" {
		t.Errorf("X-Remote-User = %q, want %q", got, "alice")
	}
}

func TestAuthMiddleware_UsernameHeader_EmptyClaim(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.UsernameHeader = "X-Remote-User"
	proxy := newTestProxy(t, cfg, pubSet)

	// Token has no username claim
	tok := mintToken(t, privKey, tokenClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	rec, upstreamHeaders := runMiddleware(t, proxy, req)

	// Request still succeeds (200) — but upstream gets empty header
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := upstreamHeaders.Get("X-Remote-User"); got != "" {
		t.Errorf("X-Remote-User = %q, want empty string for missing username claim", got)
	}
}

// ---------------------------------------------------------------------------
// RolesHeader
// ---------------------------------------------------------------------------

func TestAuthMiddleware_RolesHeader(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.RolesHeader = "X-Roles"
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{roles: []string{"admin", "editor"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	got := upstreamHeaders.Get("X-Roles")
	if got != "admin, editor" {
		t.Errorf("X-Roles = %q, want %q", got, "admin, editor")
	}
}

func TestAuthMiddleware_RolesHeader_EmptyClaim(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.Token.RolesHeader = "X-Roles"
	proxy := newTestProxy(t, cfg, pubSet)

	// Token has no roles claim
	tok := mintToken(t, privKey, tokenClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	rec, upstreamHeaders := runMiddleware(t, proxy, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := upstreamHeaders.Get("X-Roles"); got != "" {
		t.Errorf("X-Roles = %q, want empty string for missing roles claim", got)
	}
}

// ---------------------------------------------------------------------------
// AdditionalHeaders
// ---------------------------------------------------------------------------

func TestAuthMiddleware_AdditionalHeaders_Set(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AdditionalHeaders = []Header{{Name: "X-Environment", Value: "production"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if got := upstreamHeaders.Get("X-Environment"); got != "production" {
		t.Errorf("X-Environment = %q, want %q", got, "production")
	}
}

func TestAuthMiddleware_AdditionalHeaders_EmptyValueDeletes(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AdditionalHeaders = []Header{{Name: "X-Remove-Me", Value: ""}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)
	req.Header.Set("X-Remove-Me", "some-value")

	_, upstreamHeaders := runMiddleware(t, proxy, req)

	if got := upstreamHeaders.Get("X-Remove-Me"); got != "" {
		t.Errorf("X-Remove-Me = %q, want empty (should be deleted by empty additional header value)", got)
	}
}

func TestAuthMiddleware_AdditionalHeaders_EmptyNameSkipped(t *testing.T) {
	privKey, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	cfg.AdditionalHeaders = []Header{{Name: "", Value: "ignored"}}
	proxy := newTestProxy(t, cfg, pubSet)

	tok := mintToken(t, privKey, tokenClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", tok)

	rec, _ := runMiddleware(t, proxy, req)

	// Should still succeed, not panic
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// NewProxy
// ---------------------------------------------------------------------------

func TestNewProxy_ValidUpstream(t *testing.T) {
	cfg := minimalProxyConfig("http://backend.example.com")
	proxy, err := NewProxy(cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("NewProxy() returned unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("NewProxy() returned nil proxy")
	}
	if proxy.Target.Host != "backend.example.com" {
		t.Errorf("Target.Host = %q, want %q", proxy.Target.Host, "backend.example.com")
	}
}

func TestNewProxy_InvalidUpstream(t *testing.T) {
	// url.Parse never fails on garbage; use a URL with a control character to
	// force a parse error.
	cfg := minimalProxyConfig("http://bad host\x7f")
	proxy, err := NewProxy(cfg, newDiscardLogger())
	if err == nil {
		t.Error("NewProxy() expected error for invalid upstream URL, got nil")
	}
	if proxy != nil {
		t.Error("NewProxy() expected nil proxy on error")
	}
}

// ---------------------------------------------------------------------------
// loggerConfig
// ---------------------------------------------------------------------------

func TestLoggerConfig_LogValuesFunc(t *testing.T) {
	_, pubSet := generateKeyPair(t)
	cfg := minimalProxyConfig("http://backend")
	proxy := newTestProxy(t, cfg, pubSet)

	lc := proxy.loggerConfig()

	if !lc.LogStatus {
		t.Error("loggerConfig: LogStatus should be true")
	}
	if !lc.LogURI {
		t.Error("loggerConfig: LogURI should be true")
	}
	if lc.LogValuesFunc == nil {
		t.Fatal("loggerConfig: LogValuesFunc is nil")
	}

	// Exercise the LogValuesFunc to cover the log line.
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	vals := middleware.RequestLoggerValues{
		Protocol:      "HTTP/1.1",
		Method:        "GET",
		URI:           "/test",
		Status:        200,
		Latency:       50 * time.Millisecond,
		ContentLength: "42",
	}
	if err := lc.LogValuesFunc(c, vals); err != nil {
		t.Errorf("LogValuesFunc returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Run — all listeners disabled (no goroutines started, returns immediately)
// ---------------------------------------------------------------------------

func TestRun_AllListenersDisabled(t *testing.T) {
	_, pubSet := generateKeyPair(t)
	jwksPath := "/.well-known/jwks.json"
	srv := newJWKSServer(t, pubSet, jwksPath)

	cfg := &ProxyConfig{
		Upstream: "http://backend.example.com",
		Server: ServerConfig{
			ListenHttp:  "", // disabled
			ListenHttps: "", // disabled
		},
		Teleport: TeleportConfig{
			ProxyAddr:        srv.URL,
			OverrideJwksPath: jwksPath,
			TokenHeader:      "Teleport-Jwt-Assertion",
			RefreshInterval:  time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: false, // disabled
		},
	}

	proxy, err := NewProxy(cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — no servers start, errGroup.Wait() returns right away

	if err := proxy.Run(ctx); err != nil {
		t.Errorf("Run() returned unexpected error: %v", err)
	}
}

// TestRun_HTTPServer verifies that Run starts an HTTP listener and accepts a
// connection, then shuts down cleanly when the context is cancelled.
func TestRun_HTTPServer(t *testing.T) {
	_, pubSet := generateKeyPair(t)
	jwksPath := "/.well-known/jwks.json"
	jwksSrv := newJWKSServer(t, pubSet, jwksPath)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // release; the echo server will bind it

	cfg := &ProxyConfig{
		Upstream: "http://127.0.0.1:1", // unreachable backend — only testing server startup
		Server: ServerConfig{
			ListenHttp:  addr,
			ListenHttps: "",
		},
		Teleport: TeleportConfig{
			ProxyAddr:        jwksSrv.URL,
			OverrideJwksPath: jwksPath,
			TokenHeader:      "Teleport-Jwt-Assertion",
			RefreshInterval:  time.Second,
		},
		Metrics: MetricsConfig{Enabled: false},
	}

	proxy, err := NewProxy(cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- proxy.Run(ctx) }()

	// Wait until the server is accepting connections.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Signal shutdown and wait.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run() did not return within 5s after context cancel")
	}
}
