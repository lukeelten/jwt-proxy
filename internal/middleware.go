package internal

import (
	"errors"
	"strings"
)

var (
	ERR_TOKEN_EMPTY          = errors.New("missing token")
	ERR_TOKEN_INVALID        = errors.New("token invalid")
	ERR_USERNAME_NOT_ALLOWED = errors.New("user not allowed")
	ERR_ROLE_NOT_ALLOWED     = errors.New("role not allowed")
)

func CheckAllowedUsernames(acl *AccessControl, claims *TeleportClaims) error {
	if len(acl.AllowedUsers) > 0 {
		for _, username := range acl.AllowedUsers {
			if strings.Compare(username, claims.Username) == 0 {
				return nil
			}
		}

		return ERR_USERNAME_NOT_ALLOWED
	}

	return nil
}

func CheckAllowedRoles(acl *AccessControl, claims *TeleportClaims) error {
	if len(acl.AllowedRoles) > 0 {
		if len(claims.Roles) == 0 {
			return errors.New("role not allowed")
		}

		for _, allowedRole := range acl.AllowedRoles {
			for _, role := range claims.Roles {
				if strings.Compare(allowedRole, role) == 0 {
					return nil
				}
			}
		}

		return ERR_ROLE_NOT_ALLOWED
	}

	return nil
}

func ValidateRequest(validator *JWTValidator, tokenHeader string) (*TeleportClaims, error) {
	tokenHeader = strings.TrimSpace(tokenHeader)

	if len(tokenHeader) == 0 {
		return nil, ERR_TOKEN_EMPTY
	}

	if strings.HasPrefix(tokenHeader, "Bearer ") {
		tokenHeader = strings.TrimPrefix(tokenHeader, "Bearer ")
	}

	claims, err := validator.Validate(tokenHeader)
	if err != nil {
		validator.Logger.Errorw("invalid token", "err", err)
		validator.Logger.Debugw("token", "token", tokenHeader, "claims", claims)
		return nil, ERR_TOKEN_INVALID
	}

	if claims.ExpiresAt == nil {
		validator.Logger.Error("token does not have an expired field")
		validator.Logger.Debugw("token", "token", tokenHeader, "claims", claims)
		return nil, ERR_TOKEN_INVALID
	}

	return claims, nil
}
