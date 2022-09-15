package internal

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	HEADER_FORWARDED_FOR   = "X-Forwarded-For"
	HEADER_FORWARDED_HOST  = "X-Forwarded-Host"
	HEADER_FORWARDED_PROTO = "X-Forwarded-Proto"
)

type Proxy struct {
	http.Handler

	Logger *zap.SugaredLogger
	Config *ProxyConfig

	keySet        jwk.Set
	HttpServer    *http.Server
	HttpsServer   *http.Server
	Target        *url.URL
	MetricsServer *MetricsServer

	reverseProxy *httputil.ReverseProxy
}

func NewProxy(config *ProxyConfig, logger *zap.SugaredLogger) (*Proxy, error) {
	target, err := url.Parse(config.Upstream)
	if err != nil {
		logger.Errorw("invalid upstream url", "url", config.Upstream)
		return nil, err
	}

	proxy := &Proxy{
		Config:        config,
		Logger:        logger,
		reverseProxy:  httputil.NewSingleHostReverseProxy(target),
		Target:        target,
		HttpServer:    nil,
		HttpsServer:   nil,
		MetricsServer: nil,
	}

	return proxy, nil
}

func (proxy *Proxy) Run(globalContext context.Context) error {
	errGroup, ctx := errgroup.WithContext(globalContext)
	baseContextFunc := func(_ net.Listener) context.Context {
		return ctx
	}

	proxy.keySet = GetKeySet(ctx, proxy.Config.Teleport, proxy.Logger)

	if len(proxy.Config.Server.ListenHttp) > 0 {
		proxy.HttpServer = &http.Server{
			Addr:        proxy.Config.Server.ListenHttp,
			Handler:     proxy,
			BaseContext: baseContextFunc,
		}

		errGroup.Go(func() error {
			proxy.Logger.Infof("Starting HTTP Server on: %s", proxy.Config.Server.ListenHttp)
			err := proxy.HttpServer.ListenAndServe()

			if err != http.ErrServerClosed {
				proxy.Logger.Errorf("HTTP Server error: %v", err)
				return err
			}

			return nil
		})

		errGroup.Go(func() error {
			<-ctx.Done()
			err := proxy.HttpServer.Shutdown(context.Background())

			if err != nil && err != http.ErrServerClosed {
				proxy.Logger.Errorw("Got error during HTTP server shutdown", "error", err)
				return err
			}

			return nil
		})
	}

	if len(proxy.Config.Server.ListenHttps) > 0 {
		tlsConfig, err := proxy.makeTlsConfig()
		if err != nil {
			proxy.Logger.Fatalw("Cannot build required TLS Config", "err", err)
		}

		proxy.HttpsServer = &http.Server{
			Addr:        proxy.Config.Server.ListenHttps,
			Handler:     proxy,
			BaseContext: baseContextFunc,
			TLSConfig:   tlsConfig,
		}

		errGroup.Go(func() error {
			proxy.Logger.Infof("Starting HTTPS Server on: %s", proxy.Config.Server.ListenHttp)
			err := proxy.HttpsServer.ListenAndServeTLS("", "")

			if err != http.ErrServerClosed {
				proxy.Logger.Errorf("HTTPS Server error: %v", err)
				return err
			}

			return nil
		})

		errGroup.Go(func() error {
			<-ctx.Done()
			err := proxy.HttpsServer.Shutdown(context.Background())

			if err != nil && err != http.ErrServerClosed {
				proxy.Logger.Errorw("Got error during HTTPS server shutdown", "error", err)
				return err
			}

			return nil
		})
	}

	if proxy.Config.Metrics.Enabled {
		proxy.MetricsServer = NewMetricsServer(proxy.Config.Metrics, proxy.Logger)

		errGroup.Go(func() error {
			err := proxy.MetricsServer.Start()

			if err != http.ErrServerClosed {
				proxy.Logger.Errorf("Metrics Server error: %v", err)
				return err
			}

			return nil
		})

		errGroup.Go(func() error {
			<-ctx.Done()
			err := proxy.MetricsServer.Shutdown()

			if err != nil && err != http.ErrServerClosed {
				proxy.Logger.Errorw("Got error during metrics server shutdown", "error", err)
				return err
			}

			return nil
		})
	}

	// Waits until all go functions has returned. This is important to properly shut down any ongoing request
	return errGroup.Wait()
}

func (proxy *Proxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if proxy.MetricsServer != nil {
		proxy.MetricsServer.CountRequest(request)
		timer := proxy.MetricsServer.StartRequestTimer(request)
		defer func() {
			dur := timer.ObserveDuration()
			proxy.Logger.Debugw("Request completed", "duration", dur)
		}()
	}

	token, err := jwt.ParseRequest(request, jwt.WithKeySet(proxy.keySet, jws.WithRequireKid(false)), jwt.WithHeaderKey(proxy.Config.Teleport.TokenHeader))
	if err != nil {
		proxy.Logger.Debugw("debug", "err", err, "headers", request.Header)
		proxy.Unauthenticated(request, response, err)
		return
	}

	err = jwt.Validate(token, WithAllowedUsernames(proxy.Config.AccessControl), WithAllowedRoles(proxy.Config.AccessControl))
	if err != nil {
		proxy.Unauthenticated(request, response, err)
		return
	}

	proxy.Logger.Debugw("got request", "uri", request.RequestURI, "method", request.Method)

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
			proxy.Logger.Debugw("debug info", "token", token)
		}

		request.Header.Set(proxy.Config.Token.UsernameHeader, username)
	}

	// Pass roles as custom header
	if len(proxy.Config.Token.RolesHeader) > 0 {
		var roles []string
		rolesClaim, ok := token.Get(ROLES_CLAIM)
		if ok {
			if userRoles, ok := rolesClaim.([]string); ok {
				roles = userRoles
			}
		}

		if len(roles) == 0 {
			proxy.Logger.Warn("Got empty roles claim")
			proxy.Logger.Debugw("debug info", "token", token)
		}

		request.Header.Set(proxy.Config.Token.RolesHeader, strings.Join(roles, ", "))
	}

	if proxy.Config.Server.AppendProxyHeaders {
		forwardedFor := request.Header.Get(HEADER_FORWARDED_FOR)
		if len(forwardedFor) == 0 {
			request.Header.Set(HEADER_FORWARDED_FOR, request.RemoteAddr)
		}

		forwardedProto := request.Header.Get(HEADER_FORWARDED_PROTO)
		if len(forwardedProto) == 0 {
			request.Header.Set(HEADER_FORWARDED_PROTO, getRequestScheme(request))
		}

		forwardedHost := request.Header.Get(HEADER_FORWARDED_HOST)
		if len(forwardedHost) == 0 {
			request.Header.Set(HEADER_FORWARDED_HOST, request.Host)
		}
	}

	proxy.reverseProxy.ServeHTTP(response, request)
}
