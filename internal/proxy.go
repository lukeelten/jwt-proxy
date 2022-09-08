package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"strings"
)

const (
	HEADER_FORWARDED_FOR   = "X-Forwarded-For"
	HEADER_FORWARDED_HOST  = "X-Forwarded-Host"
	HEADER_FORWARDED_PROTO = "X-Forwarded-Proto"
)

func getModernTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

func getIntermediateTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

type Proxy struct {
	Config *ProxyConfig

	HttpServer  *http.Server
	HttpsServer *http.Server
	Target      *url.URL

	handleFunc http.HandlerFunc
}

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	proxy := &Proxy{
		Config: config,
	}

	target, err := url.Parse(proxy.Config.Upstream)
	if err != nil {
		return nil, err
	}

	proxy.Target = target

	return proxy, nil
}

func unauthenticated(resp http.ResponseWriter) {
	resp.WriteHeader(http.StatusUnauthorized)
	resp.Write([]byte("Unauthorized"))
}

func (proxy *Proxy) Run() error {
	reverseProxy := httputil.NewSingleHostReverseProxy(proxy.Target)
	jwtValidator := NewJWTValidator(proxy.Config.JwksUri)

	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		tokenValue := request.Header.Get(proxy.Config.TokenHeader)
		if len(tokenValue) > 0 {
			if strings.HasPrefix(tokenValue, "Bearer ") {
				tokenValue = strings.TrimPrefix(tokenValue, "Bearer ")
			}

			tokenValue = strings.TrimSpace(tokenValue)

			_, err := jwtValidator.Validate(tokenValue)
			if err != nil {
				log.Printf("Failed token validation: %v", err)
				unauthenticated(response)
				return
			}
		} else {
			unauthenticated(response)
			return
		}

		if !proxy.Config.PassToken {
			request.Header.Del(proxy.Config.TokenHeader)
		}

		forwardedFor := request.Header.Get(HEADER_FORWARDED_FOR)
		if len(forwardedFor) == 0 {
			request.Header.Set(HEADER_FORWARDED_FOR, request.RemoteAddr)
		}

		forwardedProto := request.Header.Get(HEADER_FORWARDED_PROTO)
		if len(forwardedProto) == 0 {
			request.Header.Set(HEADER_FORWARDED_PROTO, "https")
		}

		forwardedHost := request.Header.Get(HEADER_FORWARDED_HOST)
		if len(forwardedHost) == 0 {
			request.Header.Set(HEADER_FORWARDED_HOST, request.Host)
		}

		reverseProxy.ServeHTTP(response, request)
	})

	var wg sync.WaitGroup
	if proxy.Config.HttpPort > 0 {
		listenAddrHttp := fmt.Sprintf("0.0.0.0:%v", proxy.Config.HttpPort)
		proxy.HttpServer = &http.Server{
			Addr:    listenAddrHttp,
			Handler: handler,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Starting HTTP Server on: %s", listenAddrHttp)
			err := proxy.HttpServer.ListenAndServe()
			if err != http.ErrServerClosed {
				log.Printf("HTTP Server error: %v", err)
			}
		}()
	}

	if proxy.Config.HttpsPort > 0 {
		tlsConfig, err := proxy.makeTlsConfig()
		if err != nil {
			return err
		}

		listenAddrHttps := fmt.Sprintf("0.0.0.0:%v", proxy.Config.HttpsPort)
		proxy.HttpsServer = &http.Server{
			Addr:      listenAddrHttps,
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Starting HTTPS Server on: %s", listenAddrHttps)
			err := proxy.HttpsServer.ListenAndServeTLS("", "")
			if err != http.ErrServerClosed {
				log.Printf("HTTPS Server error: %v", err)
			}
		}()
	}

	exitChannel := make(chan os.Signal, 1)
	signal.Notify(exitChannel, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-exitChannel

		if proxy.Config.HttpPort > 0 {
			proxy.HttpServer.Shutdown(context.Background())
		}

		if proxy.Config.HttpsPort > 0 {
			proxy.HttpsServer.Shutdown(context.Background())
		}
	}()

	wg.Wait()
	return http.ErrServerClosed
}

func (proxy *Proxy) makeTlsConfig() (*tls.Config, error) {
	certificates := make([]tls.Certificate, 0)

	if proxy.Config.HttpsPort > 0 {
		cert, err := tls.LoadX509KeyPair(proxy.Config.CertFile, proxy.Config.KeyFile)
		if err == nil {
			return nil, err
		}

		certificates = append(certificates, cert)
	}

	var config *tls.Config
	if strings.Compare(proxy.Config.TlsProfile, "modern") == 0 {
		config = getModernTLSConfig()
	} else {
		config = getIntermediateTLSConfig()
	}

	config.Certificates = certificates

	return config, nil
}
