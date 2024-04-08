// Package asgard provides middleware for use in HTTP API servers.
// In Norse mythology, Heimdallr is the gatekeeper of Bifröst.
//
// Heimdallr returna a HTTP Handler middleware function that parses a header for
// authentication information. On success, it stores an Identity in the request context.
package asgard

import (
	"context"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

type keyClientCert struct{}

// ClientCert returns the client certificate from the request context.
// If the client certificate is not present, the second return value is false.
// Use this function to access the client certificate in a HTTP handler
// that has been wrapped with Heimdallr.
func ClientCert(ctx context.Context) (*bifrost.Certificate, bool) {
	cert, ok := ctx.Value(keyClientCert{}).(*bifrost.Certificate)
	return cert, ok
}

// Heimdallr returns a HTTP Handler middleware function that parses an AuthorizedRequestContext
// from the request context header. If namespace does not match the parsed one, the
// request is forbidden. The AuthorizedRequestContext is stored in the request context.
//
// If Heimdallr is used in an AWS Lambda Web Adapter powered API server, Bouncer Lambda Authorizer
// must be configured as an authorizer for the API Gateway method.
func Heimdallr(h HeaderName, ns uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			certHeader := r.Header.Get(h.String())
			if certHeader == "" {
				slog.ErrorContext(ctx, "missing authorization header")
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			certPEM, err := url.PathUnescape(certHeader)
			if err != nil {
				slog.ErrorContext(
					ctx, "error decoding header",
					"headerName", h.String(),
					"headerValue", certHeader,
				)
				http.Error(w, "invalid authorization header", http.StatusUnauthorized)
				return
			}

			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				slog.ErrorContext(
					ctx, "no PEM data found in authorization header",
					"headerName", h.String(),
					"headerValue", certPEM,
				)
				http.Error(w, "invalid authorization header", http.StatusUnauthorized)
				return
			}

			cert, err := bifrost.ParseCertificate(block.Bytes)
			if err != nil {
				slog.ErrorContext(ctx, "error parsing client certificate", "error", err)
				http.Error(w, "invalid authorization header", http.StatusUnauthorized)
				return
			}

			if cert.Namespace != ns {
				slog.ErrorContext(
					ctx, "client certificate namespace mismatch",
					"expected", ns,
					"actual", cert.Namespace,
				)
				http.Error(w, "incorrect namespace", http.StatusForbidden)
				return
			}

			ctx = context.WithValue(ctx, keyClientCert{}, cert)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
