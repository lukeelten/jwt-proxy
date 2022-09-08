package internal

import (
	"errors"
	"flag"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

type ProxyConfig struct {
	RequireTls  bool   `yaml:"requireTls" env:"REQUIRE_TLS" env-default:"false"`
	KeyFile     string `yaml:"keyfile" env:"KEY_FILE" env-default:"/cert/tls.key"`
	CertFile    string `yaml:"certfile" env:"CERT_FILE" env-default:"/cert/tls.crt"`
	Upstream    string `yaml:"upstream" env:"UPSTREAM"`
	HttpPort    int    `yaml:"httpPort" env:"LISTEN_PORT_HTTP" env-default:"8081"`
	HttpsPort   int    `yaml:"httpsPort" env:"LISTEN_PORT_HTTPS" env-default:"8444"`
	JwksUri     string `yaml:"jwksUri" env:"JWKS_URI"`
	TlsProfile  string `yaml:"tlsProfile" env:"TLS_PROFILE" env-default:"modern"`
	TokenHeader string `yaml:"tokenHeader" env:"TOKEN_HEADER" env-default:"Authorization"`
	PassToken   bool   `yaml:"passToken" env:"PASS_TOKEN" env-default:"false"`
}

func LoadConfig() *ProxyConfig {
	configFile := configFileName()

	var config ProxyConfig
	err := cleanenv.ReadConfig(configFile, &config)
	if err != nil {
		log.Fatal(err)
	}

	return &config
}

func configFileName() string {
	configFile := flag.String("config-file", "config.yaml", "Name or path of configuration file")
	flag.Parse()

	configFileEnv, ok := os.LookupEnv("CONFIG_FILE")
	if ok {
		return configFileEnv
	}

	return *configFile
}

func (config *ProxyConfig) Validate() error {
	config.TlsProfile = strings.ToLower(config.TlsProfile)
	if strings.Compare(config.TlsProfile, "intermediate") != 0 {
		config.TlsProfile = "modern"
	}

	if config.HttpPort < 0 || config.HttpPort > 65535 {
		return errors.New("Invalid http Port speficied")
	}

	if config.HttpsPort < 0 || config.HttpsPort > 65535 {
		return errors.New("Invalid https Port speficied")
	}

	if config.RequireTls {
		config.HttpPort = 0
	}

	if _, err := url.Parse(config.Upstream); err != nil {
		return err
	}

	if len(config.TokenHeader) == 0 {
		return errors.New("Invalid token header")
	}

	_, certErr := os.Stat(config.CertFile)
	_, keyErr := os.Stat(config.KeyFile)

	if certErr != nil || keyErr != nil {
		if config.RequireTls {
			return errors.New("invalid key or cert file given")
		} else {
			config.CertFile = ""
			config.KeyFile = ""
			config.HttpsPort = 0
			log.Print("Disable TLS Support ...")
		}
	}

	return nil
}
