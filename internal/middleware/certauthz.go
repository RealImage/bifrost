// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package middleware

import (
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/RealImage/bifrost"
	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
	"golang.org/x/net/context"
)

const ServiceUnavailableMsg = "guru meditation error"

type authzFn func(context.Context, AuthenticatedRequestContext) (events.APIGatewayCustomAuthorizerResponse, error)

// CertAuthorizer returns a Lambda Authorizer function that authorizes requests
// based on the client certificate in the request context.
// If the certificate is valid, the Authorizer returns an Allow policy.
// The the certificate namespace does not match the configured namespace,
// the Authorizer returns a Deny policy.
func CertAuthorizer(namespace uuid.UUID) authzFn {
	return func(ctx context.Context, rctx AuthenticatedRequestContext) (events.APIGatewayCustomAuthorizerResponse, error) {
		block, _ := pem.Decode([]byte(rctx.Identity.ClientCert.ClientCertPem))
		if block == nil {
			const noPem = "no PEM data found"
			slog.ErrorCtx(ctx, noPem, "len", len(rctx.Identity.ClientCert.ClientCertPem))
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(noPem)
		}
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			slog.ErrorCtx(ctx, "failed to parse certificate", "error", err)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(ServiceUnavailableMsg)
		}

		pubKey := JWKFromECDSA(cert.PublicKey)
		pubKeyStr, err := json.Marshal(pubKey)
		if err != nil {
			slog.ErrorCtx(ctx, "failed to marshal public key", "error", err)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(ServiceUnavailableMsg)
		}

		authResponse := events.APIGatewayCustomAuthorizerResponse{
			PrincipalID: cert.Id.String(),
			PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
				Version: "2012-10-17",
				Statement: []events.IAMPolicyStatement{
					{
						Action:   []string{"execute-api:Invoke"},
						Effect:   "Deny",
						Resource: []string{rctx.MethodArn},
					},
				},
			},
		}

		if cert.Namespace != namespace {
			slog.ErrorCtx(ctx,
				"certificate namespace mismatch",
				"want", namespace,
				"got", cert.Namespace,
			)
			return authResponse, nil
		}

		authResponse.PolicyDocument.Statement[0].Effect = "Allow"
		authResponse.Context = map[string]interface{}{
			"namespace": cert.Namespace.String(),
			"publicKey": string(pubKeyStr),
		}
		return authResponse, nil
	}
}
