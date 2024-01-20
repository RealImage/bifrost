package asgard

import (
	"encoding/pem"
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

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
			r.Header.Set(h.String(), string(certPEM))

			next.ServeHTTP(w, r)
		})
	}
}
