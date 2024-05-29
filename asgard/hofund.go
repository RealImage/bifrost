package asgard

import (
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

// Hofund returns a middleware that validates a client certificate
// and sets the certificate in the h request header.
//
// If a certificate is not found or is invalid, the middleware responds
// with a 401 Unauthorized.
// If the certificate namespace does not match ns, the middleware
// responds with a 403 Forbidden.
//
// Use this if you are directly serving TLS connections.
func Hofund(h HeaderName, ns uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				panic("no TLS connection or no client certificate")
			}
			ctx := r.Context()

			cert, err := bifrost.NewCertificate(r.TLS.PeerCertificates[0])
			if err != nil {
				slog.ErrorContext(ctx, "error validating client certificate", "error", err)
				http.Error(w, "invalid client certificate", http.StatusUnauthorized)
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

			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			hval := url.QueryEscape(string(certPEM))

			r.Header.Set(h.String(), hval)

			next.ServeHTTP(w, r)
		})
	}
}
