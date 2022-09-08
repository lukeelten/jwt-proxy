package main

import (
	"log"

	"github.com/lukeelten/jwt-proxy/internal"
)

func main() {
	config := internal.LoadConfig()
	err := config.Validate()
	if err != nil {
		log.Fatal(err)
	}

	proxy, err := internal.NewProxy(config)
	if err != nil {
		log.Fatal(err)
	}

	proxy.Run()
}
