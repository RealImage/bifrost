// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package asgard

import (
	"context"
	"encoding/json"
	"net/http"

	"golang.org/x/exp/slog"
)

type keyRequestContext struct{}

const (
	DefaultRequestContextHeader = "x-amzn-request-context"
)

// FromContext returns a *RequestContext from http.Request.Context.
// If it doesn't exist (i.e. Heimdall hasn't run yet), the second
// return parameter is false.
func FromContext(ctx context.Context) (r *RequestContext, ok bool) {
	r, ok = ctx.Value(keyRequestContext{}).(*RequestContext)
	return
}

// MustFromContext is identical to FromContext, except that it panics
// if the context doesn't have a RequestContext object.
// Heimdall must have run before this function is called.
func MustFromContext(ctx context.Context) *RequestContext {
	return ctx.Value(keyRequestContext{}).(*RequestContext)
}

// Heimdall returns HTTP handler middleware function that parses headerName
// as JSON into the RequestContext struct.
// If the header is missing or malformed, the middleware responds with
// a 401 Unauthorized error.
func Heimdall(headerName string) func(http.Handler) http.Handler {
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
			ctx = context.WithValue(ctx, keyRequestContext{}, &rctx)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
