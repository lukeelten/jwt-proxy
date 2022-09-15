package main

import (
	"context"
	"github.com/lukeelten/jwt-proxy/internal"
	"go.uber.org/zap"
	"log"
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

	var logger *zap.Logger
	if config.Debug {
		logger, err = zap.NewDevelopment()
	} else {
		config := zap.NewProductionConfig()
		config.Encoding = "console"
		config.EncoderConfig = zap.NewDevelopmentEncoderConfig()
		logger, err = config.Build()
	}

	if err != nil {
		log.Fatal(err)
	}

	defer logger.Sync()
	sugar := logger.Sugar()
	sugar.Debug("Enable debug mode")
	sugar.Debugw("Read Config", "config", config)

	proxy, err := internal.NewProxy(config, sugar)
	if err != nil {
		logger.Fatal(err.Error())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	err = proxy.Run(ctx)
	if err != nil && err != http.ErrServerClosed {
		sugar.Fatalw("got runtime error", "err", err)
	}
}
