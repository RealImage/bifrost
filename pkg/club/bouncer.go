// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package club provides middleware for use in HTTP API servers and gateways.
package club

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/RealImage/bifrost"
	"golang.org/x/exp/slog"
)

// Bouncer returns a HTTP Handler middleware function that adds the TLS client
// certificate from the request to the x-amzn-request-context header.
func Bouncer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			panic("bouncer operates on TLS connections with client certificates only")
		}
		peerCert := r.TLS.PeerCertificates[0]
		if _, _, err := bifrost.ValidateCertificate(peerCert); err != nil {
			err = fmt.Errorf("error validating certificate: %w", err)
			writeError(w, err, http.StatusUnauthorized, "unauthorized")
			return
		}
		requestCtx := NewRequestContext(peerCert)
		rctx, err := json.Marshal(&requestCtx)
		if err != nil {
			err = fmt.Errorf("error marshaling request context: %w", err)
			writeError(w, err, http.StatusInternalServerError, "unexpected error")
			return
		}
		r.Header.Set(RequestContextHeader, string(rctx))
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, err error, code int, msg string) {
	slog.Error(msg, "err", err)
	w.WriteHeader(code)
	if _, err := w.Write([]byte(msg)); err != nil {
		panic(err)
	}
}
