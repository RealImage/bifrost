package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/RealImage/bifrost"
	"github.com/aws/aws-lambda-go/events"
)

// BifrostAuthorizer adds the client's UUID, derived from its certificate into the response context
func BifrostAuthorizer(ctx context.Context,
	event events.APIGatewayV2CustomAuthorizerV2Request) (resp events.APIGatewayV2CustomAuthorizerSimpleResponse, err error) {
	block, _ := pem.Decode([]byte(event.RequestContext.Authentication.ClientCert.ClientCertPem))
	if block == nil {
		err = fmt.Errorf("error decoding pem client certificate from request context")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}

	pubkey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		err = fmt.Errorf("expected public key type: *ecdsa.Public")
		return
	}

	// mTLS checks should be handled by API Gateway already
	resp.IsAuthorized = true
	resp.Context = map[string]interface{}{
		"uuid": bifrost.UUID(*pubkey),
	}
	return
}
