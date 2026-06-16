package internal

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	USERNAME_CLAIM = "username"
	ROLES_CLAIM    = "roles"
)

// toStringSlice converts a JWT claim value to a []string.
// jwx v2 decodes private claims via JSON unmarshalling, so a JSON array arrives
// as []interface{} (never []string). A single string value is also handled.
func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

type allowedUsernameValidator struct {
	config AccessControl
}

func WithAllowedUsernames(acl AccessControl) jwt.ValidateOption {
	return jwt.WithValidator(&allowedUsernameValidator{config: acl})
}

func (validator *allowedUsernameValidator) Validate(ctx context.Context, token jwt.Token) jwt.ValidationError {
	if len(validator.config.AllowedUsers) == 0 {
		return nil
	}

	if usernameClaim, exists := token.Get(USERNAME_CLAIM); exists {
		if username, ok := usernameClaim.(string); ok {
			for _, allowedUsername := range validator.config.AllowedUsers {
				if allowedUsername == username {
					return nil
				}
			}

			return jwt.NewValidationError(errors.New("user not allowed"))
		}
	}

	return jwt.ErrMissingRequiredClaim(USERNAME_CLAIM)
}

type allowedRolesValidator struct {
	config AccessControl
}

func (validator *allowedRolesValidator) Validate(ctx context.Context, token jwt.Token) jwt.ValidationError {
	if len(validator.config.AllowedRoles) == 0 {
		return nil
	}

	if roleClaim, exists := token.Get(ROLES_CLAIM); exists {
		roles := toStringSlice(roleClaim)
		if roles != nil {
			for _, allowedRole := range validator.config.AllowedRoles {
				for _, role := range roles {
					if allowedRole == role {
						return nil
					}
				}
			}

			return jwt.NewValidationError(errors.New("role not allowed"))
		}
	}

	return jwt.ErrMissingRequiredClaim(ROLES_CLAIM)
}

func WithAllowedRoles(acl AccessControl) jwt.ValidateOption {
	return jwt.WithValidator(&allowedRolesValidator{config: acl})
}

// Ensure both validators satisfy the jwt.Validator interface at compile time.
var _ jwt.Validator = (*allowedUsernameValidator)(nil)
var _ jwt.Validator = (*allowedRolesValidator)(nil)
