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

type authzFn func(context.Context, AuthorizerContext) (events.APIGatewayCustomAuthorizerResponse, error)

// CertAuthorizer returns a Lambda Authorizer function that authorizes requests
// based on the client certificate in the request context.
// If the certificate is valid, the Authorizer returns an Allow policy.
// The the certificate namespace does not match the configured namespace,
// the Authorizer returns a Deny policy.
func CertAuthorizer(namespace uuid.UUID) authzFn {
	return func(ctx context.Context, authzCtx AuthorizerContext) (events.APIGatewayCustomAuthorizerResponse, error) {
		certPem := authzCtx.RequestContext.Identity.ClientCert.ClientCertPem
		block, _ := pem.Decode([]byte(certPem))
		if block == nil {
			const noPem = "no PEM data found"
			slog.ErrorCtx(ctx, noPem, "certPem", certPem)
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
			},
		}
		statement := events.IAMPolicyStatement{
			Action:   []string{"execute-api:Invoke"},
			Resource: []string{authzCtx.MethodArn},
		}

		if cert.Namespace != namespace {
			slog.ErrorCtx(ctx,
				"certificate namespace mismatch",
				"want", namespace,
				"got", cert.Namespace,
			)
			statement.Effect = "Deny"
			authResponse.PolicyDocument.Statement = []events.IAMPolicyStatement{statement}
			return authResponse, nil
		}

		slog.InfoCtx(ctx, "certificate passes the vibe check", "id", cert.Id.String())
		statement.Effect = "Allow"
		authResponse.PolicyDocument.Statement = []events.IAMPolicyStatement{statement}
		authResponse.Context = map[string]any{
			"namespace": cert.Namespace.String(),
			"publicKey": string(pubKeyStr),
		}
		return authResponse, nil
	}
}
