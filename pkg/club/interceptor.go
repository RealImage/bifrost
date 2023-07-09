// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package club

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

type Key string

const (
	keyNamespace   Key = "ns"
	keyCertificate Key = "crt"
	keyPublicKey   Key = "key"

	RequestContextHeader = "x-amzn-request-context"
)

// FromContext returns the client's UUID and Certificate from the request context.
// The context must be from a request that has passed through Interceptor.
func FromContext(ctx context.Context) (uuid.UUID, *x509.Certificate, *ecdsa.PublicKey) {
	return ctx.Value(keyNamespace).(uuid.UUID),
		ctx.Value(keyCertificate).(*x509.Certificate),
		ctx.Value(keyPublicKey).(*ecdsa.PublicKey)
}

// Interceptor returns a HTTP Handler middleware function that reads The
// x-amzn-request-context header and adds the client's UUID and certificate to
// the request context.
func Interceptor(ns uuid.UUID, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctxHeader := r.Header.Get(RequestContextHeader)
		if rctxHeader != "" {
			ctx := r.Context()
			var rctx RequestContext
			if err := json.Unmarshal([]byte(rctxHeader), &rctx); err != nil {
				slog.ErrorCtx(ctx, "error unmarshaling request context", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			block, _ := pem.Decode(rctx.Authentication.ClientCert.ClientCertPEM)
			if block == nil {
				slog.ErrorCtx(ctx, "error decoding client certificate PEM")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			cns, cert, key, err := bifrost.ParseCertificate(block.Bytes)
			if err != nil {
				slog.ErrorCtx(ctx, "error parsing client certificate", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if cns != ns {
				slog.ErrorCtx(ctx, "certificate namespace mismatch", "ns", ns, "cns", cns)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			ctx = context.WithValue(ctx, keyNamespace, cns)
			ctx = context.WithValue(ctx, keyCertificate, cert)
			ctx = context.WithValue(ctx, keyPublicKey, key)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}
