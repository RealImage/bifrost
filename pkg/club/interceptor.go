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

// ID identifies a client from the request context.
// Interceptor must run before this function is called for a request.
func ID(ctx context.Context) (uuid.UUID, *x509.Certificate, *ecdsa.PublicKey) {
	return ctx.Value(keyNamespace).(uuid.UUID),
		ctx.Value(keyCertificate).(*x509.Certificate),
		ctx.Value(keyPublicKey).(*ecdsa.PublicKey)
}

// Interceptor returns a HTTP Handler middleware function that reads The
// x-amzn-request-context header and adds the client's UUID and certificate to
// the request context.

// Interceptor is a HTTP handler middleware function that parses the
// x-amzn-request-context request header. The header is expected to contain a
// JSON encoded RequestContext. The identity namespace, client's UUID, and
// certificate are added to the request context.
func Interceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctxHeader := r.Header.Get(RequestContextHeader)
		if rctxHeader == "" {
			http.Error(w, "who is this?", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		var rctx RequestContext
		if err := json.Unmarshal([]byte(rctxHeader), &rctx); err != nil {
			slog.ErrorCtx(ctx, "error unmarshaling request context", "error", err)
			http.Error(w, "zen meditation error", http.StatusInternalServerError)
			return
		}
		block, _ := pem.Decode(rctx.Authentication.ClientCert.ClientCertPEM)
		if block == nil {
			slog.ErrorCtx(ctx, "error decoding client certificate")
			http.Error(w, "zen meditation error", http.StatusInternalServerError)
			return
		}
		ns, cert, key, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			slog.ErrorCtx(ctx, "error parsing client certificate", "error", err)
			http.Error(w, "zen meditation error", http.StatusInternalServerError)
			return
		}
		ctx = context.WithValue(ctx, keyNamespace, ns)
		ctx = context.WithValue(ctx, keyCertificate, cert)
		ctx = context.WithValue(ctx, keyPublicKey, key)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
