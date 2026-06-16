package internal

import (
	"context"
	"crypto/tls"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log/slog"
	"net/http"
	"os"
)

func GetKeySet(ctx context.Context, config TeleportConfig, logger *slog.Logger) jwk.Set {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
		},
	}

	cache := jwk.NewCache(ctx)
	err := cache.Register(config.getJwksUrl(), jwk.WithMinRefreshInterval(config.RefreshInterval), jwk.WithHTTPClient(client))
	if err != nil {
		logger.Error("cannot create key set", "err", err, "config", config)
		os.Exit(1)
	}

	return jwk.NewCachedSet(cache, config.getJwksUrl())
}
