package middleware

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
)

const (
	RequestContextHeaderName = "x-amzn-request-context"

	keyTypeEC = "EC"
	curveP256 = "P-256"
)

type AuthorizedRequestContext struct {
	Identity   AuthzIdentity `json:"identity"`
	Authorizer Authorizer    `json:"authorizer"`
}

type AuthzIdentity struct {
	SourceIP  string `json:"sourceIp"`
	UserAgent string `json:"userAgent"`
}

type Authorizer struct {
	Namespace uuid.UUID `json:"namespace"`
	PublicKey string    `json:"publicKey"`
}

type AuthorizerContext struct {
	events.APIGatewayCustomAuthorizerRequest
	RequestContext AuthorizerRequestContext `json:"requestContext"`
}

type AuthorizerRequestContext struct {
	Identity CertIdentity `json:"identity"`
}

type CertIdentity struct {
	ClientCert ClientCert `json:"clientCert"`
}

type ClientCert struct {
	ClientCertPem string `json:"clientCertPem"`
}
