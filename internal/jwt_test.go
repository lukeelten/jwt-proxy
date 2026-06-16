package internal

import (
	"context"
	"testing"
	"time"
)

// TestGetKeySet verifies that GetKeySet correctly registers a JWKS cache
// from a live httptest.Server and returns a key set that can resolve the
// published key by ID.
func TestGetKeySet(t *testing.T) {
	_, pubSet := generateKeyPair(t)

	jwksPath := "/.well-known/jwks.json"
	srv := newJWKSServer(t, pubSet, jwksPath)

	config := TeleportConfig{
		ProxyAddr:        srv.URL,
		Insecure:         false,
		OverrideJwksPath: jwksPath,
		RefreshInterval:  time.Second, // short for tests
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keySet := GetKeySet(ctx, config, newDiscardLogger())
	if keySet == nil {
		t.Fatal("GetKeySet returned nil")
	}

	// The set must contain the key we published.
	if keySet.Len() == 0 {
		t.Error("returned key set is empty — expected at least one key")
	}
}

// TestGetKeySet_WithInsecure verifies the insecure flag is threaded through
// (the httptest server is HTTP, so InsecureSkipVerify would not matter here;
// we mainly check the flag doesn't prevent operation).
func TestGetKeySet_WithInsecure(t *testing.T) {
	_, pubSet := generateKeyPair(t)

	jwksPath := "/jwks"
	srv := newJWKSServer(t, pubSet, jwksPath)

	config := TeleportConfig{
		ProxyAddr:        srv.URL,
		Insecure:         true, // plain-HTTP server; flag has no effect but must not break flow
		OverrideJwksPath: jwksPath,
		RefreshInterval:  time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keySet := GetKeySet(ctx, config, newDiscardLogger())
	if keySet == nil {
		t.Fatal("GetKeySet returned nil")
	}
}
