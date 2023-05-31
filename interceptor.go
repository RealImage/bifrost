// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bifrost

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/RealImage/bifrost/pkg/club"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

type Key string

const (
	keyUUID Key = "uuid"
	keyCert Key = "cert"
)

// FromContext returns the client's UUID and Certificate from the request context.
// The context must be from a request that has passed through Interceptor.
func FromContext(ctx context.Context) (uuid.UUID, *x509.Certificate) {
	return ctx.Value(keyUUID).(uuid.UUID), ctx.Value(keyCert).(*x509.Certificate)
}

// Interceptor returns a HTTP Handler middleware function that reads The
// x-amzn-request-context header and adds the client's UUID and certificate to
// the request context.
func Interceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctxHeader := r.Header.Get(club.RequestContextHeader)
		if rctxHeader != "" {
			ctx := r.Context()
			var rctx club.RequestContext
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
			uuid, cert, err := ParseCertificate(block.Bytes)
			if err != nil {
				slog.ErrorCtx(ctx, "error parsing client certificate", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			ctx = context.WithValue(ctx, keyUUID, uuid)
			ctx = context.WithValue(ctx, keyCert, cert)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}
