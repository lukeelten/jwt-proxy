package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GetKeySet(ctx context.Context, config TeleportConfig, logger *slog.Logger) (jwk.Set, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
		},
	}

	jwksUrl := config.getJwksUrl()
	logger.Info("registering JWKS cache", "url", jwksUrl, "refreshInterval", config.RefreshInterval)

	cache := jwk.NewCache(ctx)
	err := cache.Register(jwksUrl, jwk.WithMinRefreshInterval(config.RefreshInterval), jwk.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("cannot register JWKS cache: %w", err)
	}

	return jwk.NewCachedSet(cache, jwksUrl), nil
}
