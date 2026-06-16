package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo-contrib/v5/echoprometheus"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/sync/errgroup"
)

type Proxy struct {
	http.Handler

	Logger *slog.Logger
	Config *ProxyConfig

	keySet jwk.Set
	Target *url.URL
}

func NewProxy(config *ProxyConfig, logger *slog.Logger) (*Proxy, error) {
	target, err := url.Parse(config.Upstream)
	if err != nil {
		logger.Error("invalid upstream url", "url", config.Upstream)
		return nil, err
	}

	proxy := &Proxy{
		Config: config,
		Logger: logger,
		Target: target,
	}

	return proxy, nil
}

func (proxy *Proxy) Run(globalContext context.Context) error {
	errGroup, ctx := errgroup.WithContext(globalContext)

	proxy.keySet = GetKeySet(ctx, proxy.Config.Teleport, proxy.Logger)
	proxyTargets := []*middleware.ProxyTarget{
		{
			URL: proxy.Target,
		},
	}

	if len(proxy.Config.Server.ListenHttp) > 0 {
		httpServer := echo.New()
		httpServer.Use(echoprometheus.NewMiddleware("jwt_proxy_http"))
		httpServer.Use(middleware.Recover())
		httpServer.Use(middleware.RequestLoggerWithConfig(proxy.loggerConfig()))
		httpServer.Use(proxy.authenticationMiddleware)
		httpServer.Use(middleware.Proxy(middleware.NewRandomBalancer(proxyTargets)))

		errGroup.Go(func() error {
			proxy.Logger.Info("Starting HTTP Server", "addr", proxy.Config.Server.ListenHttp)

			startConfig := echo.StartConfig{
				Address:    proxy.Config.Server.ListenHttp,
				HideBanner: true,
				HidePort:   true,
			}

			err := startConfig.Start(ctx, httpServer)

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				proxy.Logger.Error("HTTP Server error", "err", err)
				return err
			}

			return nil
		})
	}

	if len(proxy.Config.Server.ListenHttps) > 0 {
		httpsServer := echo.New()
		httpsServer.Use(echoprometheus.NewMiddleware("jwt_proxy_https"))
		httpsServer.Use(middleware.Recover())
		httpsServer.Use(middleware.RequestLoggerWithConfig(proxy.loggerConfig()))
		httpsServer.Use(proxy.authenticationMiddleware)
		httpsServer.Use(middleware.Proxy(middleware.NewRandomBalancer(proxyTargets)))

		errGroup.Go(func() error {
			proxy.Logger.Info("Starting HTTPS Server", "addr", proxy.Config.Server.ListenHttps)

			startConfig := echo.StartConfig{
				Address:    proxy.Config.Server.ListenHttps,
				HideBanner: true,
				HidePort:   true,
			}

			err := startConfig.StartTLS(ctx, httpsServer, proxy.Config.Server.CertFile, proxy.Config.Server.KeyFile)

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				proxy.Logger.Error("HTTPS Server error", "err", err)
				return err
			}

			return nil
		})
	}

	if proxy.Config.Metrics.Enabled {
		metricsServer := echo.New()
		metricsServer.Use(echoprometheus.NewMiddleware("jwt_proxy_metrics"))
		metricsServer.Use(middleware.Recover())
		metricsServer.GET("/metrics", echoprometheus.NewHandler())

		errGroup.Go(func() error {
			startConfig := echo.StartConfig{
				Address:    proxy.Config.Metrics.ListenAddr,
				HideBanner: true,
				HidePort:   true,
			}
			err := startConfig.Start(ctx, metricsServer)

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				proxy.Logger.Error("Metrics Server error", "err", err)
				return err
			}

			return nil
		})
	}

	// Waits until all go functions has returned. This is important to properly shut down any ongoing request
	return errGroup.Wait()
}

func (proxy *Proxy) authenticationMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		request := c.Request()
		token, err := jwt.ParseRequest(request, jwt.WithKeySet(proxy.keySet, jws.WithRequireKid(false)), jwt.WithHeaderKey(proxy.Config.Teleport.TokenHeader))
		if err != nil {
			proxy.Logger.Debug("unauthenticated", "err", err, "headers", request.Header)
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		err = jwt.Validate(token, WithAllowedUsernames(proxy.Config.AccessControl), WithAllowedRoles(proxy.Config.AccessControl))
		if err != nil {
			proxy.Logger.Debug("unauthenticated", "err", err, "headers", request.Header)
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		// Unconditionally strip all identity/auth headers that this proxy may
		// set, so clients cannot spoof them regardless of which features are
		// enabled. Trusted values are written back below.
		request.Header.Del("Authorization")
		if len(proxy.Config.Token.PassTokenAsHeader) > 0 {
			request.Header.Del(proxy.Config.Token.PassTokenAsHeader)
		}
		if len(proxy.Config.Token.UsernameHeader) > 0 {
			request.Header.Del(proxy.Config.Token.UsernameHeader)
		}
		if len(proxy.Config.Token.RolesHeader) > 0 {
			request.Header.Del(proxy.Config.Token.RolesHeader)
		}

		// Pass Token to Upstream
		if !proxy.Config.Token.PassToken {
			request.Header.Del(proxy.Config.Teleport.TokenHeader)
		}

		// Pass Token as Authorization Bearer
		if proxy.Config.Token.PassAsBearer {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", request.Header.Get(proxy.Config.Teleport.TokenHeader)))
		}

		// Pass Token as custom header
		if len(proxy.Config.Token.PassTokenAsHeader) > 0 {
			request.Header.Set(proxy.Config.Token.PassTokenAsHeader, fmt.Sprintf("Bearer %s", request.Header.Get(proxy.Config.Teleport.TokenHeader)))
		}

		// Pass username as custom header
		if len(proxy.Config.Token.UsernameHeader) > 0 {
			var username string
			usernameClaim, ok := token.Get(USERNAME_CLAIM)
			if ok {
				if user, ok := usernameClaim.(string); ok {
					username = user
				}
			}

			if len(username) == 0 {
				proxy.Logger.Warn("Got empty username claim")
				proxy.Logger.Debug("debug info", "token", token)
			}

			request.Header.Set(proxy.Config.Token.UsernameHeader, username)
		}

		// Pass roles as custom header
		if len(proxy.Config.Token.RolesHeader) > 0 {
			var roles []string
			rolesClaim, ok := token.Get(ROLES_CLAIM)
			if ok {
				roles = toStringSlice(rolesClaim)
			}

			if len(roles) == 0 {
				proxy.Logger.Warn("Got empty roles claim")
				proxy.Logger.Debug("debug info", "token", token)
			}

			request.Header.Set(proxy.Config.Token.RolesHeader, strings.Join(roles, ", "))
		}

		// append additional header
		for _, header := range proxy.Config.AdditionalHeaders {
			if len(header.Name) == 0 {
				continue
			}

			if len(header.Value) == 0 {
				request.Header.Del(header.Name)
			} else {
				request.Header.Set(header.Name, header.Value)
			}
		}

		return next(c)
	}
}

func (proxy *Proxy) loggerConfig() middleware.RequestLoggerConfig {
	loggerConfig := middleware.RequestLoggerConfig{
		LogStatus: true,
		LogURI:    true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			proxy.Logger.Info("request", "protocol", v.Protocol, "method", v.Method, "uri", v.URI, "status", v.Status, "latency", v.Latency.String(), "content_length", v.ContentLength)
			return nil
		},
	}

	return loggerConfig
}
