package middleware

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/RealImage/bifrost"
	"github.com/VictoriaMetrics/metrics"
	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
	"golang.org/x/net/context"
)

const (
	ServiceUnavailableMsg = "guru meditation error"

	bfErrPrefix = "bifrost: "
)

// nsMetricsMap is a map of namespace to metrics.
var nsMetricsMap = sync.Map{}

type nsAuthzMetrics struct {
	allowed *metrics.Counter
	denied  *metrics.Counter
	error   *metrics.Counter
}

func getNsAuthzMetrics(namespace uuid.UUID) *nsAuthzMetrics {
	m, ok := nsMetricsMap.Load(namespace)
	if !ok {
		m = &nsAuthzMetrics{
			allowed: bifrost.StatsForNerds.NewCounter(
				fmt.Sprintf(`bifrost_authz_allowed{namespace="%s"}`, namespace),
			),
			denied: bifrost.StatsForNerds.NewCounter(
				fmt.Sprintf(`bifrost_authz_denied{namespace="%s"}`, namespace),
			),
			error: bifrost.StatsForNerds.NewCounter(
				fmt.Sprintf(`bifrost_authz_error{namespace="%s"}`, namespace),
			),
		}
		nsMetricsMap.Store(namespace, m)
	}
	return m.(*nsAuthzMetrics)
}

type authzFn func(context.Context, AuthorizerContext) (events.APIGatewayCustomAuthorizerResponse, error)

// CertAuthorizer returns a Lambda Authorizer function that authorizes requests
// based on the client certificate in the request context.
// If the certificate is valid, the Authorizer returns an Allow policy.
// The the certificate namespace does not match the configured namespace,
// the Authorizer returns a Deny policy.
func CertAuthorizer(namespace uuid.UUID) authzFn {
	m := getNsAuthzMetrics(namespace)
	return func(ctx context.Context, authzCtx AuthorizerContext) (events.APIGatewayCustomAuthorizerResponse, error) {
		certPem := authzCtx.RequestContext.Identity.ClientCert.ClientCertPem
		block, _ := pem.Decode([]byte(certPem))
		if block == nil {
			m.error.Inc()
			const noPem = "no PEM data found"
			slog.ErrorContext(ctx, noPem, "certPem", certPem)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(bfErrPrefix + noPem)
		}
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			m.error.Inc()
			slog.ErrorContext(ctx, "failed to parse certificate", "error", err)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(
				bfErrPrefix + ServiceUnavailableMsg,
			)
		}

		pubKey := JWKFromECDSA(cert.PublicKey)
		pubKeyStr, err := json.Marshal(pubKey)
		if err != nil {
			m.error.Inc()
			slog.ErrorContext(ctx, "failed to marshal public key", "error", err)
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New(
				bfErrPrefix + ServiceUnavailableMsg,
			)
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
			m.denied.Inc()
			slog.ErrorContext(ctx,
				"certificate namespace mismatch",
				"want", namespace,
				"got", cert.Namespace,
			)
			statement.Effect = "Deny"
			authResponse.PolicyDocument.Statement = []events.IAMPolicyStatement{statement}
			return authResponse, nil
		}

		m.allowed.Inc()
		slog.InfoContext(ctx, "certificate passes the vibe check", "id", cert.Id.String())
		statement.Effect = "Allow"
		authResponse.PolicyDocument.Statement = []events.IAMPolicyStatement{statement}
		authResponse.Context = map[string]any{
			"namespace": cert.Namespace.String(),
			"publicKey": string(pubKeyStr),
		}
		return authResponse, nil
	}
}
