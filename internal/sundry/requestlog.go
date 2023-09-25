// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sundry

import (
	"net/http"
	"time"

	"golang.org/x/exp/slog"
)

// RequestLogHandler logs the request method and uri to stdout.
func RequestLogHandler(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		slog.InfoCtx(
			r.Context(),
			"request received",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Duration("duration", time.Since(start)),
		)
	}
	return http.HandlerFunc(fn)
}
