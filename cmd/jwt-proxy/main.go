package main

import (
	"github.com/lukeelten/jwt-proxy/internal"
	"go.uber.org/zap"
	"log"
)

func main() {
	config := internal.LoadConfig()
	err := config.Validate()
	if err != nil {
		log.Fatal(err)
	}

	var logger *zap.Logger
	if config.Debug {
		logger, _ = zap.NewDevelopment()
		logger.Info("Enable Debug Mode")
	} else {
		logger, _ = zap.NewProduction()
	}
	defer logger.Sync()

	logger.Sugar().Debugw("Read Config", "config", config)

	proxy, err := internal.NewProxy(config, logger.Sugar())
	if err != nil {
		logger.Fatal(err.Error())
	}

	proxy.Run()
}
