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

// CertAuthorizer returns a Lambda Authorizer function that authorizes requests
// based on the client certificate.
func CertAuthorizer(
	namespace uuid.UUID,
) func(context.Context, AuthenticatedRequestContext) (events.APIGatewayCustomAuthorizerResponse, error) {
	return func(ctx context.Context, rctx AuthenticatedRequestContext) (events.APIGatewayCustomAuthorizerResponse, error) {
		block, _ := pem.Decode([]byte(rctx.Authentication.ClientCert.ClientCertPem))
		if block == nil {
			slog.ErrorCtx(ctx, "failed to parse certificate PEM")
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(
				"failed to parse certificate PEM",
			)
		}
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			slog.ErrorCtx(ctx, "failed to parse certificate", "error", err)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(ServiceUnavailableMsg)
		}

		var pubKey JWK
		pubKey.FromECDSA(cert.PublicKey)
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
