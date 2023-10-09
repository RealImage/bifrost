// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const (
	RequestContextHeaderName = "x-amzn-request-context"

	keyTypeEC = "EC"
	curveP256 = "P-256"
)

type AuthorizedRequestContext struct {
	Identity struct {
		SourceIp  string `json:"sourceIp"`
		UserAgent string `json:"userAgent"`
	} `json:"identity"`
	Authorizer Authorizer `json:"authorizer"`
}

type Authorizer struct {
	Namespace uuid.UUID `json:"namespace"`
	PublicKey JWK       `json:"publicKey"`
}

// JWK is a JSON Web Key.
// It is a subset of the JWK spec, containing only the fields we need.
// See https://tools.ietf.org/html/rfc7517#section-4.1 for the full spec.
// JWK marshals to and unmarshals from a JSON string.
type JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

type jwkAlias JWK

func (j JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(jwkAlias(j))
}

func (j *JWK) UnmarshalJSON(data []byte) error {
	var jwk jwkAlias
	if err := json.Unmarshal(data, &jwk); err != nil {
		return err
	}
	if jwk.KeyType != keyTypeEC {
		return fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}
	if jwk.Curve != curveP256 {
		return fmt.Errorf("unsupported curve: %s", jwk.Curve)
	}
	if jwk.X == "" || jwk.Y == "" {
		return fmt.Errorf("missing coordinates")
	}
	*j = JWK(jwk)
	return nil
}

func (j JWK) ToECDSA() (*ecdsa.PublicKey, bool) {
	var x, y big.Int
	if _, ok := x.SetString(j.X, 10); !ok {
		return nil, ok
	}
	if _, ok := y.SetString(j.Y, 10); !ok {
		return nil, ok
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}, true
}

func (j *JWK) FromECDSA(key *ecdsa.PublicKey) {
	j.KeyType = keyTypeEC
	j.Curve = curveP256
	j.X = key.X.String()
	j.Y = key.Y.String()
}

func JWKFromECDSA(key *ecdsa.PublicKey) JWK {
	var j JWK
	j.FromECDSA(key)
	return j
}

type AuthenticatedRequestContext struct {
	events.APIGatewayCustomAuthorizerRequest
	Identity CertIdentity `json:"identity"`
}

func (a *AuthenticatedRequestContext) UnmarshalJSON(data []byte) error {
	slog.Info("unmarshaling request context", "data", string(data))
	type alias AuthenticatedRequestContext
	var ctx alias
	if err := json.Unmarshal(data, &ctx); err != nil {
		return err
	}
	*a = AuthenticatedRequestContext(ctx)
	return nil
}

type CertIdentity struct {
	ClientCert ClientCert `json:"clientCert"`
}

// ClientCert contains fields related to TLS Client Certificates.
type ClientCert struct {
	ClientCertPem string   `json:"clientCertPem"`
	SubjectDN     string   `json:"subjectDN"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	Validity      Validity `json:"validity"`
}

type Validity struct {
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}
