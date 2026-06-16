package internal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
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
