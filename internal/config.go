package internal

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

const DEFAULT_CONFIG_FILE_NAME = "config.yaml"

type ProxyConfig struct {
	Upstream string `yaml:"upstream" env:"UPSTREAM" env-required:""`
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
	KeyFile    string `yaml:"keyFile" env:"KEY_FILE" env-default:"/cert/tls.key"`
	CertFile   string `yaml:"certFile" env:"CERT_FILE" env-default:"/cert/tls.crt"`

	ListenHttp  string `yaml:"listenHttp" env:"LISTEN_HTTP" env-default:"0.0.0.0:8081"`
	ListenHttps string `yaml:"listenHttps" env:"LISTEN_HTTPS" env-default:"0.0.0.0:8444"`
	TlsProfile  string `yaml:"tlsProfile" env:"TLS_PROFILE" env-default:"modern"`

	AppendProxyHeaders bool `yaml:"appendProxyHeaders" env:"PROXY_APPEND_HEADERS" env-default:"true"`
}

type TeleportConfig struct {
	ProxyAddr        string        `yaml:"proxyAddr" env:"TELEPORT_HOST" env-required:""`
	Insecure         bool          `yaml:"insecure" env:"TELEPORT_INSECURE" env-default:"false"`
	OverrideJwksPath string        `yaml:"overrideJwksPath" env:"TELEPORT_JWKS_PATH" env-default:""`
	TokenHeader      string        `yaml:"tokenHeader" env:"TELEPORT_TOKEN_HEADER" env-default:"Teleport-Jwt-Assertion"`
	RefreshInterval  time.Duration `yaml:"refreshInterval" env:"TELEPORT_REFRESH_INTERVAL" env-default:"15m"`
}

type AccessControl struct {
	AllowedUsers []string `yaml:"allowedUsers" env:"ALLOWED_USERS" env-default:""`
	AllowedRoles []string `yaml:"allowedRoles" env:"ALLOWED_ROLES" env-default:""`
}

type TokenConfig struct {
	PassToken         bool   `yaml:"passToken" env:"PASS_TOKEN" env-default:"false"`
	PassTokenAsHeader string `yaml:"passTokenAsHeader" env:"PASS_TOKEN_AS_HEADER" env-default:""`
	PassAsBearer      bool   `yaml:"passAsBearer" env:"PASS_TOKEN_AS_BEARER" env-default:"false"`
	UsernameHeader    string `yaml:"usernameHeader" env:"PASS_USERNAME_HEADER" env-default:""`
	RolesHeader       string `yaml:"rolesHeader" env:"PASS_ROLES_HEADER" env-default:""`
}

type MetricsConfig struct {
	Enabled        bool   `yaml:"enabled" env:"METRICS_ENABLED" env-default:"true"`
	ListenAddr     string `yaml:"listenAddr" env:"METRICS_LISTEN_ADDR" env-default:"0.0.0.0:9090"`
	Endpoint       string `yaml:"endpoint" env:"METRICS_ENDPOINT" env-default:"/metrics"`
	HealthEndpoint string `yaml:"healthEndpoint" env:"HEALTH_ENDPOINT" env-default:"/health"`
}

type Header struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

func LoadConfig() *ProxyConfig {
	cfg, err := loadConfigFrom(configFileName())
	if err != nil {
		log.Fatal(err)
	}
	return cfg
}

// loadConfigFrom is the testable core of LoadConfig. It resolves the config
// file path, falls back to DEFAULT_CONFIG_FILE_NAME when present, then reads
// the configuration from either the file or the environment. It returns an
// error instead of calling log.Fatal so callers in tests can assert on it.
func loadConfigFrom(configFile string) (*ProxyConfig, error) {
	if len(configFile) > 0 {
		if _, err := os.Stat(configFile); err != nil {
			return nil, fmt.Errorf("cannot find config file %q: %w", configFile, err)
		}
	} else {
		if _, err := os.Stat(DEFAULT_CONFIG_FILE_NAME); err == nil {
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
		return nil, err
	}

	return &config, nil
}

func configFileName() string {
	return resolveConfigFile(os.Args[1:], os.LookupEnv)
}

// resolveConfigFile determines the config file path from CLI args and the
// environment. It is a pure function with injected dependencies so it can be
// tested without touching global flag.CommandLine or os.Args.
//
// Priority: CLI flag --config-file > CONFIG_FILE env var > empty string.
func resolveConfigFile(args []string, lookupEnv func(string) (string, bool)) string {
	fs := flag.NewFlagSet("jwt-proxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress usage output during tests
	configFile := fs.String("config-file", "", "Name or path of configuration file")
	// Ignore parse errors (e.g. unknown flags from the test runner).
	_ = fs.Parse(args)

	if len(*configFile) > 0 {
		return *configFile
	}

	if configFileEnv, ok := lookupEnv("CONFIG_FILE"); ok && len(configFileEnv) > 0 {
		return configFileEnv
	}

	return ""
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
		log.Print("RequireTls=true: disabling plain HTTP listener")
	}

	if u, err := url.ParseRequestURI(config.Upstream); err != nil || u.Scheme == "" || u.Host == "" {
		if err != nil {
			return fmt.Errorf("invalid upstream url: %w", err)
		}
		return fmt.Errorf("invalid upstream url %q: scheme and host are required", config.Upstream)
	}

	if len(config.Teleport.TokenHeader) == 0 {
		return errors.New("invalid token header")
	}

	if len(config.Teleport.ProxyAddr) == 0 || (config.Teleport.Insecure && strings.HasPrefix(config.Teleport.ProxyAddr, "http")) {
		return errors.New("invalid teleport config")
	}

	if config.Teleport.Insecure {
		log.Print("WARNING: teleport.insecure=true — TLS certificate verification for the JWKS endpoint is disabled. " +
			"A MITM attacker could serve forged keys and bypass JWT authentication. Do not use in production.")
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
