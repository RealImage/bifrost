// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package club provides middleware for use in HTTP API servers and gateways.
package club

import (
	"encoding/json"
	"encoding/pem"
	"net/http"

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
		var requestCtx RequestContext
		requestCtx.Authentication.ClientCert = ClientCert{
			ClientCertPEM: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: peerCert.Raw,
			}),
			IssuerDN:     peerCert.Issuer.ToRDNSequence().String(),
			SerialNumber: peerCert.Issuer.SerialNumber,
			SubjectDN:    peerCert.Subject.ToRDNSequence().String(),
			Validity: validity{
				NotAfter:  peerCert.NotAfter,
				NotBefore: peerCert.NotBefore,
			},
		}
		rctx, err := json.Marshal(&requestCtx)
		if err != nil {
			slog.Error("error marshaling request context", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("unexpected error handling request")); err != nil {
				panic(err)
			}
			return
		}
		r.Header.Set(RequestContextHeader, string(rctx))
		next.ServeHTTP(w, r)
	})
}
