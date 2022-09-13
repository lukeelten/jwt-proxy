package internal

import (
	"context"
	"crypto/tls"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
	"net/http"
	"time"
)

type JWTValidator struct {
	Logger   *zap.SugaredLogger
	jwksUrl  string
	insecure bool

	shutdownFunc context.CancelFunc
	keysCache    jwk.Set
}

type TeleportClaims struct {
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

func NewJWTValidator(config TeleportConfig, logger *zap.SugaredLogger) *JWTValidator {
	jva := &JWTValidator{
		jwksUrl:  config.getJwksUrl(),
		insecure: config.Insecure,
		Logger:   logger,
	}

	ctx, cancel := context.WithCancel(context.TODO())
	jva.shutdownFunc = cancel

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: jva.insecure,
			},
		},
	}

	cache := jwk.NewCache(ctx)
	err := cache.Register(config.getJwksUrl(), jwk.WithMinRefreshInterval(60*time.Minute), jwk.WithHTTPClient(client))
	if err != nil {
		logger.Fatalw("cannot create key set", "err", err, "config", config)
	}

	jva.keysCache = jwk.NewCachedSet(cache, config.getJwksUrl())

	return jva
}

func (jva *JWTValidator) Shutdown() {
	jva.shutdownFunc()
}

func (jva *JWTValidator) Parse(tokenString string) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(jva.keysCache))
	return token, err
}
