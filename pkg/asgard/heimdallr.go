// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package asgard provides middleware for use in HTTP API servers.
// In Norse mythology, Heimdallr is the gatekeeper of Bifröst.
//
// Heimdallr returna a HTTP Handler middleware function that parses a header for
// authentication information. On success, it stores an Identity in the request context.
package asgard

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"

	"github.com/RealImage/bifrost/internal/middleware"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

type Identity struct {
	Namespace uuid.UUID
	PublicKey *ecdsa.PublicKey
	SourceIp  string
	UserAgent string
}

type keyAuthz struct{}

// FromContext returns an Identity from the request context.
// If the request context does not contain an AuthorizedRequestContext,
// the second return value is false.
func FromContext(ctx context.Context) (*Identity, bool) {
	authz := ctx.Value(keyAuthz{})
	if authz == nil {
		return nil, false
	}
	a, ok := authz.(middleware.AuthorizedRequestContext)
	if !ok {
		return nil, false
	}
	key, ok := a.Authorizer.PublicKey.ToECDSA()
	if !ok {
		return nil, false
	}
	id := &Identity{
		Namespace: a.Authorizer.Namespace,
		PublicKey: key,
		SourceIp:  a.Identity.SourceIp,
		UserAgent: a.Identity.UserAgent,
	}
	return id, true
}

// MustFromContext is like FromContext but panics if the request context
// does not contain an AuthorizedRequestContext.
func MustFromContext(ctx context.Context) *Identity {
	id, ok := FromContext(ctx)
	if !ok {
		panic("no public key in context")
	}
	return id
}

// Heimdallr returns a HTTP Handler middleware function that parses an AuthorizedRequestContext
// from headerName. If namespace does not match the parsed one, the request is forbidden.
// The AuthorizedRequestContext is stored in the request context.
//
// If Heimdallr is used in an AWS Lambda Web Adapter powered API server, Bouncer Lambda Authorizer
// must be configured as an authorizer for the API Gateway method.
func Heimdallr(headerName string, namespace uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get(headerName)
			if hdr == "" {
				http.Error(w, middleware.ServiceUnavailableMsg, http.StatusServiceUnavailable)
				return
			}
			ctx := r.Context()
			var rctx middleware.AuthorizedRequestContext
			if err := json.Unmarshal([]byte(hdr), &rctx); err != nil {
				slog.ErrorCtx(ctx, "error unmarshaling request context", "error", err)
				http.Error(w, middleware.ServiceUnavailableMsg, http.StatusServiceUnavailable)
				return
			}
			if rctx.Authorizer.Namespace != namespace {
				slog.ErrorCtx(ctx,
					"namespace mismatch",
					"want", namespace,
					"got", rctx.Authorizer.Namespace,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			ctx = context.WithValue(ctx, keyAuthz{}, rctx)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
