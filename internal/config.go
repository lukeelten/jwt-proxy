package internal

import (
	"crypto/tls"
	"errors"
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

const DEFAULT_CONFIG_FILE_NAME = "config.yaml"

type ProxyConfig struct {
	Upstream string `yaml:"upstream" env:"UPSTREAM" env-required`
	Debug    bool   `yaml:"debug" env:"DEBUG" env-default:"false"`

	Metrics MetricsConfig `yaml:"metrics"`

	Server            ServerConfig   `yaml:"server"`
	Teleport          TeleportConfig `yaml:"teleport"`
	AccessControl     AccessControl  `yaml:"accessControl"`
	Token             TokenConfig    `yaml:"token"`
	AdditionalHeaders []Header       `yaml:"additionalHeaders"`
}

type ServerConfig struct {
	RequireTls bool   `yaml:"requireTls" env:"REQUIRE_TLS" env-default:"false"`
	KeyFile    string `yaml:"keyfile" env:"KEY_FILE" env-default:"/cert/tls.key"`
	CertFile   string `yaml:"certfile" env:"CERT_FILE" env-default:"/cert/tls.crt"`

	ListenHttp  string `yaml:"listenHttp" env:"LISTEN_HTTP" env-default:"0.0.0.0:8081"`
	ListenHttps string `yaml:"listenHttps" env:"LISTEN_HTTPS" env-default:"0.0.0.0:8444"`
	TlsProfile  string `yaml:"tlsProfile" env:"TLS_PROFILE" env-default:"modern"`

	AppendProxyHeaders bool `yaml:"appendProxyHeaders" env:"PROXY_APPEND_HEADERS" env-default:"true"`
}

type TeleportConfig struct {
	ProxyAddr        string        `yaml:"proxyAddr" env:"TELEPORT_HOST" env-required`
	Insecure         bool          `yaml:"insecure" env:"TELEPORT_INSECURE" env-default:"false"`
	OverrideJwksPath string        `yaml:"overrideJwksPath" env:"TELEPORT_JWKS_PATH" env-default:""`
	TokenHeader      string        `yaml:"tokenHeader" env:"TELEPORT_TOKEN_HEADER" env-default:"Teleport-Jwt-Assertion"`
	RefreshInternal  time.Duration `yaml:"refreshInternal" env:"TELEPORT_REFRESH_INTERVAL" env-default:"15m"`
}

type AccessControl struct {
	AllowedUsers []string `yaml:"allowedUsers" env-default:""`
	AllowedRoles []string `yaml:"allowedRoles" env-default:""`
}

type TokenConfig struct {
	PassToken         bool   `yaml:"passToken" env:"PASS_TOKEN" env-default:"false"`
	PassTokenAsHeader string `yaml:"passTokenAsHeader" env:"PASS_TOKEN_AS_HEADER" env-default:""`
	PassAsBearer      bool   `yaml:"passAsBearer" env:"PASS_TOKEN_AS_BEARER" env-default:"false"`
	UsernameHeader    string `yaml:"usernameHeader" env:"PASS_USERNAME_HEADER" env-default:""`
	RolesHeader       string `yaml:"rolesHeader" env:"PASS_ROLES_HEADER" env-default:""`
}

type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled" env:"METRICS_ENABLED" env-default:"true"`
	ListenAddr string `yaml:"listenAddr" env:"METRICS_LISTEN_ADDR" env-default:"0.0.0.0:9090"`
	Endpoint   string `yaml:"endpoint" env:"METRICS_ENDPOINT" env-default:"/metrics"`
}

type Header struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

func LoadConfig() *ProxyConfig {
	configFile := configFileName()
	if len(configFile) > 0 {
		_, err := os.Stat(configFile)
		if err != nil {
			log.Fatal("Cannot find given config file: %v", configFile)
		}
	} else {
		_, err := os.Stat(DEFAULT_CONFIG_FILE_NAME)
		if err == nil {
			configFile = DEFAULT_CONFIG_FILE_NAME
		}
	}

	var config ProxyConfig
	var err error
	if len(configFile) > 0 {
		log.Printf("Load Config from File: %s", configFile)
		err = cleanenv.ReadConfig(configFile, &config)
	} else {
		log.Print("Load Config from Environment")
		err = cleanenv.ReadEnv(&config)
	}

	if err != nil {
		log.Fatal(err)
	}

	return &config
}

func configFileName() string {
	configFile := flag.String("config-file", "", "Name or path of configuration file")
	flag.Parse()

	configFileEnv, ok := os.LookupEnv("CONFIG_FILE")
	if ok {
		return configFileEnv
	}

	return *configFile
}

func (t TeleportConfig) getJwksUrl() string {
	var jwksUrl string = ""
	if !strings.HasPrefix(t.ProxyAddr, "http") {
		jwksUrl += "https://"
	}

	jwksUrl += strings.TrimSuffix(t.ProxyAddr, "/")
	if len(t.OverrideJwksPath) == 0 {
		jwksUrl += "/.well-known/jwks.json"
	} else {
		if !strings.HasPrefix(t.OverrideJwksPath, "/") {
			jwksUrl += "/"
		}

		jwksUrl += t.OverrideJwksPath
	}

	return jwksUrl
}

func (t TeleportConfig) getTlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: t.Insecure,
	}
}

func (config *ProxyConfig) Validate() error {
	if config.Server.RequireTls {
		config.Server.ListenHttp = ""
	}

	if _, err := url.Parse(config.Upstream); err != nil {
		return err
	}

	if len(config.Teleport.TokenHeader) == 0 {
		return errors.New("invalid token header")
	}

	if len(config.Teleport.ProxyAddr) == 0 || (config.Teleport.Insecure && strings.HasPrefix(config.Teleport.ProxyAddr, "http")) {
		return errors.New("invalid teleport config")
	}

	_, certErr := os.Stat(config.Server.CertFile)
	_, keyErr := os.Stat(config.Server.KeyFile)

	if certErr != nil || keyErr != nil {
		if config.Server.RequireTls {
			return errors.New("cannot find key or cert file")
		} else {
			config.Server.ListenHttps = ""
			log.Print("Disable TLS Support ...")
		}
	}

	return nil
}
