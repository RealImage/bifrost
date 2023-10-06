// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package asgard provides middleware for use in HTTP API servers and reverse-proxies.
// In Norse mythology, Heimdallr is the gatekeeper of Bifröst and Hofund is his sword.
//
// Heimdallr returna a HTTP Handler middleware function that parses a header into a RequestContext.
// Hofund returns a HTTP Handler middleware function that writes a RequestContext into a header
// from a client's TLS certificate.
package asgard

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

// Heimdallr returns a HTTP handler middleware function that parses headerName
// as JSON into the RequestContext struct.
// If the header is missing or malformed, the middleware responds with
// a 401 Unauthorized error.
func Heimdallr(headerName string, namespace uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		const newPhoneWhoDis = "new phone who dis?"
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get(headerName)
			if hdr == "" {
				http.Error(w, newPhoneWhoDis, http.StatusUnauthorized)
				return
			}
			ctx := r.Context()
			var rctx RequestContext
			if err := json.Unmarshal([]byte(hdr), &rctx); err != nil {
				slog.ErrorCtx(ctx, "error unmarshaling request context", "error", err)
				http.Error(w, newPhoneWhoDis, http.StatusUnauthorized)
				return
			}
			if rctx.ClientCert != nil && rctx.ClientCert.Namespace != namespace {
				slog.ErrorCtx(
					ctx,
					"client certificate namespace mismatch",
					"expected",
					namespace,
					"actual",
					rctx.ClientCert.Namespace,
				)
				http.Error(w, "incorrect namespace", http.StatusForbidden)
				return
			}
			ctx = context.WithValue(ctx, keyRequestContext{}, &rctx)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
