package internal

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type JWTValidator struct {
	Logger          *zap.SugaredLogger
	publicKeys      []Key
	mutex           sync.RWMutex
	jwksUrl         string
	insecure        bool
	shutdownChannel chan bool
}

type TeleportClaims struct {
	jwt.RegisteredClaims

	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

type Key struct {
	Id  string
	Key *rsa.PublicKey
}

// jwk is a JSON Web Key, described in detail in RFC 7517.
type jwk struct {
	KeyId string `json:"kid,omitempty"`
	// KeyType is the type of asymmetric key used.
	KeyType string `json:"kty"`
	// Algorithm used to sign.
	Algorithm string `json:"alg"`
	Usage     string `json:"use,omitempty"`
	// N is the modulus of the public key.
	N string `json:"n"`
	// E is the exponent of the public key.
	E string `json:"e"`
}

// jwksResponse is the response format for the JWK endpoint.
type jwksResponse struct {
	// Keys is a list of public keys in JWK format.
	Keys []jwk `json:"keys"`
}

func NewJWTValidator(config TeleportConfig, logger *zap.SugaredLogger) *JWTValidator {
	jva := &JWTValidator{
		jwksUrl:         config.getJwksUrl(),
		insecure:        config.Insecure,
		shutdownChannel: make(chan bool, 1),
		Logger:          logger,
	}

	// Initially load the keys
	jva.refreshKey()

	// Start thread which refreshes the key every interval
	go func() {
		for {
			select {
			case <-jva.shutdownChannel:
				// exit go routine on shutdown
				return

			case <-time.After(config.RefreshInternal):
				// Reload keys after time period
				jva.refreshKey()
			}
		}
	}()

	return jva
}

func (jva *JWTValidator) Shutdown() {
	jva.shutdownChannel <- true
}

func (jva *JWTValidator) refreshKey() {
	jva.Logger.Infow("Loading JWKS Key", "url", jva.jwksUrl, "insecure", jva.insecure)

	keys, err := jva.loadKeys()
	if err != nil {
		jva.Logger.Fatalw("cannot read public keys", "err", err, "url", jva.jwksUrl, "insecure", jva.insecure)
	}

	jva.Logger.Debugw("Got keys", "keys", keys)

	jva.mutex.Lock()
	defer jva.mutex.Unlock()
	jva.publicKeys = keys
}

func (jva *JWTValidator) Validate(tokenString string) (*TeleportClaims, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		jva.mutex.RLock()
		defer jva.mutex.RUnlock()

		kidValue, okGet := token.Header["kid"]
		kid, okCast := kidValue.(string)
		if !okGet || !okCast || len(kid) == 0 {
			if len(jva.publicKeys) > 0 {
				return jva.publicKeys[0].Key, nil
			} else {
				jva.Logger.Debugw("cannot find any matching key", "token", token, "keys", jva.publicKeys)
				return nil, errors.New("cannot find suitable key")
			}
		}

		for _, key := range jva.publicKeys {
			if strings.Compare(kid, key.Id) == 0 {
				return key.Key, nil
			}
		}

		jva.Logger.Debugw("cannot find requested key", "token", token, "keys", jva.publicKeys)
		return nil, errors.New("cannot find required key")
	}

	var claims TeleportClaims
	_, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
	if err != nil {
		jva.Logger.Debugw("cannot validate token", "err", err, "claims", claims, "token", tokenString)
		return nil, err
	}

	return &claims, claims.Valid()
}

func (key jwk) getKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}

	e, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Uint64()),
	}, nil
}

func (jva *JWTValidator) loadKeys() ([]Key, error) {
	// Fetch JWKs.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: jva.insecure,
			},
		},
	}
	resp, err := client.Get(jva.jwksUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if len(response.Keys) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	keys := make([]Key, 0)
	for _, k := range response.Keys {
		if strings.Compare(strings.ToUpper(k.Algorithm), "RSA") != 0 {
			// We only support RSA
			continue
		}

		publickey, err := k.getKey()
		if err != nil {
			return nil, err
		}

		keys = append(keys, Key{Key: publickey, Id: k.KeyId})
	}

	return keys, nil
}
