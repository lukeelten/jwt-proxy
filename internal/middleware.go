package internal

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"strings"
)

const (
	USERNAME_CLAIM = "username"
	ROLES_CLAIM    = "roles"
)

type allowedUsernameValidator struct {
	jwt.Validator
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
				if strings.Compare(allowedUsername, username) == 0 {
					return nil
				}
			}

			return jwt.NewValidationError(errors.New("user not allowed"))
		}
	}

	return jwt.ErrMissingRequiredClaim(USERNAME_CLAIM)
}

type allowedRolesValidator struct {
	jwt.Validator
	config AccessControl
}

func (validator allowedRolesValidator) Validate(ctx context.Context, token jwt.Token) jwt.ValidationError {
	if len(validator.config.AllowedRoles) == 0 {
		return nil
	}

	if roleClaim, exists := token.Get(ROLES_CLAIM); exists {
		if roles, ok := roleClaim.([]string); ok {
			for _, allowedRole := range validator.config.AllowedRoles {
				for _, role := range roles {
					if strings.Compare(allowedRole, role) == 0 {
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
