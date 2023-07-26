// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package club

import (
	"context"
	"encoding/json"
	"net/http"

	"golang.org/x/exp/slog"
)

type keyRequestContext struct{}

const (
	RequestContextHeader = "x-amzn-request-context"
)

// FromContext identifies a client from the request context.
// Interceptor must run before this function is called for a request.
func FromContext(ctx context.Context) (r *RequestContext, ok bool) {
	r, ok = ctx.Value(keyRequestContext{}).(*RequestContext)
	return
}

// MustFromContext is identical to FromContext, except that it panics
// if the context doesn't have a RequestContext object.
func MustFromContext(ctx context.Context) *RequestContext {
	return ctx.Value(keyRequestContext{}).(*RequestContext)
}

// Interceptor is a HTTP handler middleware function that parses the
// x-amzn-request-context request header. The header is expected to contain a
// JSON encoded RequestContext. The identity namespace, client's UUID, and
// certificate are added to the request context.
func Interceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctxHeader := r.Header.Get(RequestContextHeader)
		if rctxHeader == "" {
			http.Error(w, "new phone who dis?", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		var rctx RequestContext
		if err := json.Unmarshal([]byte(rctxHeader), &rctx); err != nil {
			slog.ErrorCtx(ctx, "error unmarshaling request context", "error", err)
			http.Error(w, "zen meditation error", http.StatusInternalServerError)
			return
		}
		ctx = context.WithValue(ctx, keyRequestContext{}, &rctx)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
