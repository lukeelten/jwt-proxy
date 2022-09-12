/*
Copyright 2020 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Source: https://github.com/gravitational/teleport/blob/v10.1.9/examples/jwt/verify-jwt.go
*/

package internal

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"math/big"
	"net/http"
	"sync/atomic"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type JWTValidator struct {
	Logger          *zap.SugaredLogger
	publicKey       atomic.Value
	jwksUrl         string
	insecure        bool
	shutdownChannel chan bool
}

type TeleportClaims struct {
	jwt.RegisteredClaims

	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
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
	jva.Logger.Info("Loading JWKS Key", "url", jva.jwksUrl, "insecure", jva.insecure)

	key, err := getPublicKey(jva.jwksUrl, jva.insecure)
	if err != nil {
		jva.Logger.Fatalw("cannot read public keys", "err", err, "url", jva.jwksUrl, "insecure", jva.insecure)
	}

	jva.Logger.Debugw("Got key", "key", key)

	jva.publicKey.Store(key)
}

func (jva *JWTValidator) Validate(tokenString string) (*TeleportClaims, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return jva.publicKey.Load(), nil
	}

	var claims TeleportClaims
	_, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
	if err != nil {
		return nil, err
	}

	return &claims, claims.Valid()
}

// jwk is a JSON Web Key, described in detail in RFC 7517.
type jwk struct {
	// KeyType is the type of asymmetric key used.
	KeyType string `json:"kty"`
	// Algorithm used to sign.
	Algorithm string `json:"alg"`
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

// claims represents public and private claims for a JWT token.
type claims struct {
	// Claims represents public claim values (as specified in RFC 7519).
	jwt.Claims

	// Username returns the Teleport identity of the user.
	Username string `json:"username"`

	// Roles returns the list of roles assigned to the user within Teleport.
	Roles []string `json:"roles"`
}

// @todo support for multiple keys
// getPublicKey fetches the public key from the JWK endpoint.
func getPublicKey(url string, insecureSkipVerify bool) (*rsa.PublicKey, error) {
	// Fetch JWKs.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse JWKs response.
	var response jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if len(response.Keys) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	// Construct a crypto.PublicKey from the response.
	jwk := response.Keys[0]
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Uint64()),
	}, nil
}
