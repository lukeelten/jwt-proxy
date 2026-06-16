package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// newDiscardLogger returns a *slog.Logger that silently discards all output.
func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// generateKeyPair generates an RSA key pair and returns:
//   - privKey: the private jwk.Key (with kid="test-kid") for signing
//   - pubSet:  a jwk.Set containing only the public key for verification
func generateKeyPair(t *testing.T) (jwk.Key, jwk.Set) {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	privKey, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw(private): %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, "test-kid"); err != nil {
		t.Fatalf("set kid on private key: %v", err)
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg on private key: %v", err)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	pubSet := jwk.NewSet()
	if err := pubSet.AddKey(pubKey); err != nil {
		t.Fatalf("add public key to set: %v", err)
	}

	return privKey, pubSet
}

// tokenClaims holds optional overrides for mintToken.
type tokenClaims struct {
	subject  string
	username string
	roles    []string
	expiry   time.Time
}

// mintToken signs a JWT with the given private key and claims.
// Returns the compact serialised token string.
func mintToken(t *testing.T, privKey jwk.Key, claims tokenClaims) string {
	t.Helper()

	b := jwt.NewBuilder()

	sub := claims.subject
	if sub == "" {
		sub = "test-subject"
	}
	b.Subject(sub)

	exp := claims.expiry
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	b.Expiration(exp)
	b.IssuedAt(time.Now())

	if claims.username != "" {
		b.Claim(USERNAME_CLAIM, claims.username)
	}
	if len(claims.roles) > 0 {
		b.Claim(ROLES_CLAIM, claims.roles)
	}

	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}

// newJWKSServer starts an httptest.Server that serves pubSet as a JWKS JSON
// document at the given path (e.g. "/.well-known/jwks.json").
// The server is registered for automatic cleanup with t.Cleanup.
func newJWKSServer(t *testing.T, pubSet jwk.Set, path string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(pubSet)
		if err != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// minimalProxyConfig returns a *ProxyConfig wired with the given key set,
// ready for use in unit tests of authenticationMiddleware. The returned config
// leaves all optional header features disabled by default so individual tests
// can opt in by mutating the returned struct.
func minimalProxyConfig(upstream string) *ProxyConfig {
	return &ProxyConfig{
		Upstream: upstream,
		Teleport: TeleportConfig{
			TokenHeader: "Teleport-Jwt-Assertion",
		},
	}
}

// resetFlags resets the global flag.CommandLine so that configFileName can
// re-register the "config-file" flag without panicking. The original
// flag.CommandLine is restored after the test.
func resetFlags(t *testing.T) {
	t.Helper()
	old := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(old.Name(), flag.ContinueOnError)
	t.Cleanup(func() { flag.CommandLine = old })
}

// unsetEnv temporarily removes each named environment variable for the
// duration of the test. t.Setenv restores the original value on cleanup;
// we additionally call os.Unsetenv so the variable is truly absent (not
// just set to an empty string) during the test.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		orig, existed := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unsetenv %s: %v", k, err)
		}
		if existed {
			t.Cleanup(func() { _ = os.Setenv(k, orig) })
		}
	}
}
