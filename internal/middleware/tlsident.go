package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

// TLSIdentifier returns a HTTP Handler middleware function that identifies clients using
// TLS client certificates.
// It parses the client certficiate into a RequestContext which is
// JSON-serialised into the request context header.
func TLSIdentifier(namespace uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				panic("no TLS connection or no client certificate")
			}
			ctx := r.Context()
			cert := &bifrost.Certificate{
				Certificate: r.TLS.PeerCertificates[0],
			}
			if err := cert.Verify(); err != nil {
				slog.ErrorContext(ctx, "error validating client certificate", "error", err)
				http.Error(w, "invalid client certificate", http.StatusUnauthorized)
				return
			}

			if cert.Namespace != namespace {
				slog.ErrorContext(
					ctx,
					"client certificate namespace mismatch",
					"expected",
					namespace,
					"actual",
					cert.Namespace,
				)
				http.Error(w, "incorrect namespace", http.StatusForbidden)
				return
			}

			j := JWKFromECDSA(cert.PublicKey)
			val, err := json.Marshal(j)
			if err != nil {
				slog.ErrorContext(ctx, "error marshaling public key", "error", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}

			rctx := AuthorizedRequestContext{
				Authorizer: Authorizer{
					PublicKey: string(val),
				},
			}

			rctxHeader, err := json.Marshal(&rctx)
			if err != nil {
				slog.ErrorContext(ctx, "error marshaling request context", "error", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			r.Header.Set(RequestContextHeaderName, string(rctxHeader))
			next.ServeHTTP(w, r)
		})
	}
}
