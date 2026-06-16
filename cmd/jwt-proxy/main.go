package main

import (
	"context"
	"github.com/lukeelten/jwt-proxy/internal"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := internal.LoadConfig()
	err := config.Validate()
	if err != nil {
		log.Fatal(err)
	}

	logLevel := slog.LevelInfo
	if config.Debug {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	logger.Debug("Enable debug mode")
	logger.Debug("Read Config", "config", config)

	proxy, err := internal.NewProxy(config, logger)
	if err != nil {
		logger.Error("failed to create proxy", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	err = proxy.Run(ctx)
	if err != nil && err != http.ErrServerClosed {
		logger.Error("got runtime error", "err", err)
		os.Exit(1)
	}
}
