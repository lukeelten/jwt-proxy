package internal

import (
	"context"
	"crypto/tls"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/zap"
	"net/http"
)

func GetKeySet(ctx context.Context, config TeleportConfig, logger *zap.SugaredLogger) jwk.Set {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
		},
	}

	cache := jwk.NewCache(ctx)
	err := cache.Register(config.getJwksUrl(), jwk.WithMinRefreshInterval(config.RefreshInternal), jwk.WithHTTPClient(client))
	if err != nil {
		logger.Fatalw("cannot create key set", "err", err, "config", config)
	}

	return jwk.NewCachedSet(cache, config.getJwksUrl())
}
