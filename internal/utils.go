package internal

import (
	"crypto/tls"
	"net/http"
	"strings"
)

func (proxy *Proxy) makeTlsConfig() (*tls.Config, error) {
	certificates := make([]tls.Certificate, 0)
	cert, err := tls.LoadX509KeyPair(proxy.Config.Server.CertFile, proxy.Config.Server.KeyFile)
	if err == nil {
		return nil, err
	}

	certificates = append(certificates, cert)

	var config *tls.Config
	if strings.Compare(proxy.Config.Server.TlsProfile, "intermediate") == 0 {
		config = getIntermediateTLSConfig()
	} else {
		config = getModernTLSConfig()
	}

	config.Certificates = certificates

	proxy.Logger.Debugw("created TLS config", "config", config)

	return config, nil
}

func getModernTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

func getIntermediateTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

func getRequestScheme(request *http.Request) string {
	if len(request.URL.Scheme) == 0 {
		if request.TLS != nil {
			return "https"
		}

		return "http"
	}

	return strings.ToLower(request.URL.Scheme)
}

func (proxy *Proxy) Unauthenticated(request *http.Request, resp http.ResponseWriter, authError error) {
	proxy.Logger.Debugw("Create error response", "err", authError)
	if proxy.MetricsServer != nil {
		proxy.MetricsServer.CountError(request)
	}

	resp.WriteHeader(http.StatusUnauthorized)
	_, err := resp.Write([]byte("Unauthorized"))

	if err != nil {
		proxy.Logger.Errorw("Got error writing response body", "err", err)
	}
}
