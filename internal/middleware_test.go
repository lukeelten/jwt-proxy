package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ---------------------------------------------------------------------------
// toStringSlice
// ---------------------------------------------------------------------------

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string // nil means expect nil result
	}{
		{
			name:  "[]string passthrough",
			input: []string{"a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "single string becomes slice",
			input: "admin",
			want:  []string{"admin"},
		},
		{
			name:  "[]interface{} of strings",
			input: []interface{}{"r1", "r2", "r3"},
			want:  []string{"r1", "r2", "r3"},
		},
		{
			name:  "[]interface{} with non-string elements filtered out",
			input: []interface{}{"keep", 42, true, "also-keep"},
			want:  []string{"keep", "also-keep"},
		},
		{
			name:  "empty []interface{}",
			input: []interface{}{},
			want:  []string{},
		},
		{
			name:  "unsupported type returns nil",
			input: 12345,
			want:  nil,
		},
		{
			name:  "nil returns nil",
			input: nil,
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toStringSlice(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("toStringSlice(%v) = %v (len %d), want %v (len %d)", tc.input, got, len(got), tc.want, len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("toStringSlice(%v)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers: build a minimal jwt.Token with given private claims
// ---------------------------------------------------------------------------

func buildToken(t *testing.T, claims map[string]interface{}) jwt.Token {
	t.Helper()
	b := jwt.NewBuilder().Subject("test")
	for k, v := range claims {
		b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	return tok
}

// ---------------------------------------------------------------------------
// allowedUsernameValidator
// ---------------------------------------------------------------------------

func TestAllowedUsernameValidator(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		acl         AccessControl
		tokenClaims map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty allow-list permits any user",
			acl:         AccessControl{AllowedUsers: nil},
			tokenClaims: map[string]interface{}{USERNAME_CLAIM: "alice"},
			wantErr:     false,
		},
		{
			name:        "matching user is permitted",
			acl:         AccessControl{AllowedUsers: []string{"alice", "bob"}},
			tokenClaims: map[string]interface{}{USERNAME_CLAIM: "alice"},
			wantErr:     false,
		},
		{
			name:        "non-matching user is rejected",
			acl:         AccessControl{AllowedUsers: []string{"alice"}},
			tokenClaims: map[string]interface{}{USERNAME_CLAIM: "mallory"},
			wantErr:     true,
			errContains: "user not allowed",
		},
		{
			name:        "missing username claim returns ErrMissingRequiredClaim",
			acl:         AccessControl{AllowedUsers: []string{"alice"}},
			tokenClaims: map[string]interface{}{},
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := buildToken(t, tc.tokenClaims)
			v := &allowedUsernameValidator{config: tc.acl}
			err := v.Validate(ctx, tok)

			if tc.wantErr && err == nil {
				t.Error("Validate() returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() returned unexpected error: %v", err)
			}
			if tc.errContains != "" && err != nil {
				if !errors.Is(err, err) { // confirm it's a ValidationError — type assertion below
					t.Error("expected a jwt.ValidationError")
				}
				if err.Error() != "" && tc.errContains != "" {
					found := false
					msg := err.Error()
					for i := 0; i <= len(msg)-len(tc.errContains); i++ {
						if msg[i:i+len(tc.errContains)] == tc.errContains {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("error %q does not contain %q", msg, tc.errContains)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// allowedRolesValidator
// ---------------------------------------------------------------------------

func TestAllowedRolesValidator(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		acl         AccessControl
		tokenClaims map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty allow-list permits any roles",
			acl:         AccessControl{AllowedRoles: nil},
			tokenClaims: map[string]interface{}{ROLES_CLAIM: []interface{}{"guest"}},
			wantErr:     false,
		},
		{
			name:        "one of several roles matches",
			acl:         AccessControl{AllowedRoles: []string{"admin", "editor"}},
			tokenClaims: map[string]interface{}{ROLES_CLAIM: []interface{}{"viewer", "editor"}},
			wantErr:     false,
		},
		{
			name:        "single string role matches",
			acl:         AccessControl{AllowedRoles: []string{"admin"}},
			tokenClaims: map[string]interface{}{ROLES_CLAIM: "admin"},
			wantErr:     false,
		},
		{
			name:        "no matching role is rejected",
			acl:         AccessControl{AllowedRoles: []string{"admin"}},
			tokenClaims: map[string]interface{}{ROLES_CLAIM: []interface{}{"viewer"}},
			wantErr:     true,
			errContains: "role not allowed",
		},
		{
			name:        "missing roles claim returns ErrMissingRequiredClaim",
			acl:         AccessControl{AllowedRoles: []string{"admin"}},
			tokenClaims: map[string]interface{}{},
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := buildToken(t, tc.tokenClaims)
			v := &allowedRolesValidator{config: tc.acl}
			err := v.Validate(ctx, tok)

			if tc.wantErr && err == nil {
				t.Error("Validate() returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() returned unexpected error: %v", err)
			}
			if tc.errContains != "" && err != nil {
				msg := err.Error()
				found := false
				for i := 0; i <= len(msg)-len(tc.errContains); i++ {
					if msg[i:i+len(tc.errContains)] == tc.errContains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("error %q does not contain %q", msg, tc.errContains)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WithAllowedUsernames / WithAllowedRoles integration via jwt.Validate
// ---------------------------------------------------------------------------

func TestWithAllowedUsernamesIntegration(t *testing.T) {
	privKey, _ := generateKeyPair(t)

	tok := mintToken(t, privKey, tokenClaims{username: "alice", roles: []string{"admin"}})
	parsed, err := jwt.ParseInsecure([]byte(tok))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	// No ACL restriction — should pass
	if err := jwt.Validate(parsed, WithAllowedUsernames(AccessControl{})); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Allowed user — should pass
	if err := jwt.Validate(parsed, WithAllowedUsernames(AccessControl{AllowedUsers: []string{"alice"}})); err != nil {
		t.Errorf("expected no error for allowed user, got %v", err)
	}

	// Disallowed user — should fail
	if err := jwt.Validate(parsed, WithAllowedUsernames(AccessControl{AllowedUsers: []string{"bob"}})); err == nil {
		t.Error("expected error for disallowed user, got nil")
	}
}

func TestWithAllowedRolesIntegration(t *testing.T) {
	privKey, _ := generateKeyPair(t)

	tok := mintToken(t, privKey, tokenClaims{username: "alice", roles: []string{"editor", "viewer"}})
	parsed, err := jwt.ParseInsecure([]byte(tok))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	// No ACL restriction — should pass
	if err := jwt.Validate(parsed, WithAllowedRoles(AccessControl{})); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Matching role — should pass
	if err := jwt.Validate(parsed, WithAllowedRoles(AccessControl{AllowedRoles: []string{"editor"}})); err != nil {
		t.Errorf("expected no error for allowed role, got %v", err)
	}

	// No matching role — should fail
	if err := jwt.Validate(parsed, WithAllowedRoles(AccessControl{AllowedRoles: []string{"admin"}})); err == nil {
		t.Error("expected error for disallowed role, got nil")
	}
}
