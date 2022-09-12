package internal

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type MetricsServer struct {
	Config MetricsConfig
	Logger *zap.SugaredLogger

	server         *http.Server
	shutdownSignal chan bool

	RequestCounter       *prometheus.CounterVec
	RequestDuration      *prometheus.HistogramVec
	AuthenticationErrors *prometheus.CounterVec
}

func NewMetricsServer(config MetricsConfig, logger *zap.SugaredLogger) *MetricsServer {
	logger.Debugw("Creating new metrics server", "config", config)
	serveMux := http.NewServeMux()
	serveMux.Handle(config.Endpoint, promhttp.Handler())

	server := &http.Server{
		Addr:    config.ListenAddr,
		Handler: serveMux,
	}

	return &MetricsServer{
		Config:               config,
		Logger:               logger,
		server:               server,
		shutdownSignal:       make(chan bool, 1),
		RequestCounter:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "proxy_requests"}, []string{"path", "method", "proto"}),
		RequestDuration:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "proxy_requests_duration"}, []string{"path", "method", "proto"}),
		AuthenticationErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "proxy_authentication_errors"}, []string{"path", "method", "proto", "error"}),
	}
}

func (server *MetricsServer) Start() error {
	if !server.Config.Enabled {
		server.Logger.Warn("Cannot start metrics server. Config says its disabled")
		return nil
	}

	// Register generic go collectors
	prometheus.MustRegister(collectors.NewBuildInfoCollector())
	prometheus.MustRegister(collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics()))

	// Register custom metrics
	prometheus.MustRegister(server.RequestCounter)
	prometheus.MustRegister(server.RequestDuration)
	prometheus.MustRegister(server.AuthenticationErrors)

	server.Logger.Infow("Starting metrics server ...", "addr", server.Config.ListenAddr, "endpoint", server.Config.ListenAddr)
	return server.server.ListenAndServe()
}

func (server *MetricsServer) Shutdown() error {
	return server.server.Shutdown(context.Background())
}

func (server *MetricsServer) CountRequest(request *http.Request) {
	server.RequestCounter.WithLabelValues(
		request.URL.Path,
		strings.ToUpper(request.Method),
		strings.ToLower(request.URL.Scheme),
	).Inc()
}

func (server *MetricsServer) CountError(request *http.Request, err error) {
	server.RequestCounter.WithLabelValues(
		request.URL.Path,
		strings.ToUpper(request.Method),
		strings.ToLower(request.URL.Scheme),
		err.Error(),
	).Inc()
}

func (server *MetricsServer) StartRequestTimer(request *http.Request) *prometheus.Timer {
	observer := server.RequestDuration.WithLabelValues(
		request.URL.Path,
		strings.ToUpper(request.Method),
		strings.ToLower(request.URL.Scheme),
	)

	return prometheus.NewTimer(observer)
}