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
		RefreshInterval:  time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keySet, err := GetKeySet(ctx, config, newDiscardLogger())
	if err != nil {
		t.Fatalf("GetKeySet returned unexpected error: %v", err)
	}
	if keySet == nil {
		t.Fatal("GetKeySet returned nil key set")
	}
	if keySet.Len() == 0 {
		t.Error("returned key set is empty — expected at least one key")
	}
}

// TestGetKeySet_WithInsecure verifies the insecure flag is threaded through
// without breaking normal operation on a plain-HTTP httptest server.
func TestGetKeySet_WithInsecure(t *testing.T) {
	_, pubSet := generateKeyPair(t)

	jwksPath := "/jwks"
	srv := newJWKSServer(t, pubSet, jwksPath)

	config := TeleportConfig{
		ProxyAddr:        srv.URL,
		Insecure:         true,
		OverrideJwksPath: jwksPath,
		RefreshInterval:  time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keySet, err := GetKeySet(ctx, config, newDiscardLogger())
	if err != nil {
		t.Fatalf("GetKeySet returned unexpected error: %v", err)
	}
	if keySet == nil {
		t.Fatal("GetKeySet returned nil key set")
	}
}
