package asgard

import (
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

func Hofund(namespace uuid.UUID, h HeaderName) func(http.Handler) http.Handler {
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
					ctx, "client certificate namespace mismatch",
					"expected", namespace,
					"actual", cert.Namespace,
				)
				http.Error(w, "incorrect namespace", http.StatusForbidden)
				return
			}

			r.Header.Set(h.String(), string("todo"))

			next.ServeHTTP(w, r)
		})
	}
}
