// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package club provides middleware for use in HTTP API servers and gateways.
package club

import (
	"encoding/json"
	"net/http"

	"github.com/RealImage/bifrost"
	"golang.org/x/exp/slog"
)

// Bouncer returns a HTTP Handler middleware function that adds the TLS client
// certificate from the request to the x-amzn-request-context header.
func Bouncer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			panic("bouncer works only on TLS servers with clients connecting with certificates")
		}
		ctx := r.Context()
		peerCert := r.TLS.PeerCertificates[0]
		if _, _, err := bifrost.ValidateCertificate(peerCert); err != nil {
			slog.ErrorCtx(ctx, "error validating client certificate", "error", err)
			http.Error(w, "invalid client certificate", http.StatusUnauthorized)
		}
		requestCtx := NewRequestContext(peerCert)
		rctx, err := json.Marshal(&requestCtx)
		if err != nil {
			slog.ErrorCtx(r.Context(), "error marshaling request context", "error", err)
			http.Error(w, "unexpected error", http.StatusInternalServerError)
			return
		}
		r.Header.Set(RequestContextHeader, string(rctx))
		next.ServeHTTP(w, r)
	})
}
