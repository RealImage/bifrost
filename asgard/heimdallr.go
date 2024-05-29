// Package asgard provides middleware for use in HTTP API servers
// that require client certificate (mTLS) authentication.
//
// In Norse mythology Heimdallr is the gatekeeper of the celestial bridge, the Bifröst.
// Hofund is Heimdallr's sword. No mythical significance, just a cool name.
//
// Here Heimdallr returns a middleware that parses client certs from a request header.
// Hofund returns a middleware that parses client certs from the TLS connection.
// Use Heimdallr if you have a reverse proxy that terminates TLS connections.
// Use Hofund if you are directly serving TLS connections.
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

const errBadAuthHeader = "missing or invalid authorization information, server is misconfigured"

type keyClientCert struct{}

// ClientCert returns the client certificate from the request context.
// If the client certificate is not present, the second return value is false.
// Use this function to access the client certificate in a HTTP handler
// that has been wrapped with Heimdallr.
func ClientCert(ctx context.Context) (*bifrost.Certificate, bool) {
	cert, ok := ctx.Value(keyClientCert{}).(*bifrost.Certificate)
	return cert, ok
}

// Heimdallr returns a middleware that parses a client certificate from the
// h request header.
//
// If a certificate is not found or is invalid, the middleware responds
// with a 503 Service Unavailable.
// If the certificate namespace does not match ns, the middleware
// responds with a 403 Forbidden.
//
// Use this if you have a reverse proxy that terminates TLS connections and
// passes the client certificate in a request header.
func Heimdallr(h HeaderName, ns uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			certHeader := r.Header.Get(h.String())
			if certHeader == "" {
				slog.ErrorContext(ctx, "missing authorization header")
				http.Error(w, errBadAuthHeader, http.StatusServiceUnavailable)
				return
			}

			certPEM, err := url.PathUnescape(certHeader)
			if err != nil {
				slog.ErrorContext(
					ctx, "error decoding header",
					"headerName", h.String(),
					"headerValue", certHeader,
				)
				http.Error(w, errBadAuthHeader, http.StatusServiceUnavailable)
				return
			}

			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				slog.ErrorContext(
					ctx, "no PEM data found in authorization header",
					"headerName", h.String(),
					"headerValue", certPEM,
				)
				http.Error(w, errBadAuthHeader, http.StatusServiceUnavailable)
				return
			}

			cert, err := bifrost.ParseCertificate(block.Bytes)
			if err != nil {
				slog.ErrorContext(ctx, "error parsing client certificate", "error", err)
				http.Error(w, errBadAuthHeader, http.StatusServiceUnavailable)
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
