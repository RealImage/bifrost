// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

// TLSIdentifier returns a HTTP Handler middleware function that identifies clients using
// TLS client certificates.
// It parses the client certficiate into a RequestContext which is
// JSON-serialised into the headerName header.
func TLSIdentifier(headerName string, namespace uuid.UUID) func(http.Handler) http.Handler {
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
				slog.ErrorCtx(ctx, "error validating client certificate", "error", err)
				http.Error(w, "invalid client certificate", http.StatusUnauthorized)
				return
			}

			if cert.Namespace != namespace {
				slog.ErrorCtx(
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

			var j JWK
			j.FromECDSA(cert.PublicKey)

			rctx := AuthorizedRequestContext{
				Authorizer: Authorizer{
					PublicKey: j,
				},
			}

			rctxHeader, err := json.Marshal(&rctx)
			if err != nil {
				slog.ErrorCtx(ctx, "error marshaling request context", "error", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			r.Header.Set(headerName, string(rctxHeader))
			next.ServeHTTP(w, r)
		})
	}
}
