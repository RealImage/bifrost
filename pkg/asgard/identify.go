// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package club provides middleware for use in HTTP API servers and gateways.
package asgard

import (
	"encoding/json"
	"net/http"

	"github.com/RealImage/bifrost"
	"golang.org/x/exp/slog"
)

// Identify returns a HTTP Handler middleware function that identifies clients
// by their TLS client certificates.
// It parses the client certficiate into a RequestContext which is
// JSON-serialised into the headerName header.
func Identify(headerName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				panic("bouncer works only on TLS servers with clients connecting with certificates")
			}
			ctx := r.Context()
			peerCert := r.TLS.PeerCertificates[0]
			ns, key, err := bifrost.ValidateCertificate(peerCert)
			if err != nil {
				slog.ErrorCtx(ctx, "error validating client certificate", "error", err)
				http.Error(w, "invalid client certificate", http.StatusUnauthorized)
				return
			}

			rctx := RequestContext{
				ClientCertificate: peerCert,
				ClientPublicKey:   key,
				Namespace:         ns,
				SourceIP:          r.RemoteAddr,
				UserAgent:         r.UserAgent(),
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
