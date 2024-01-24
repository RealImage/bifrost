package webapp

import (
	"log/slog"
	"net/http"

	"github.com/felixge/httpsnoop"
)

// RequestLogHandler logs the request method and uri to stdout.
func RequestLogHandler(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(h, w, r)
		slog.InfoContext(
			r.Context(), "request",
			"method", r.Method,
			"uri", r.RequestURI,
			"status", m.Code,
			"duration", m.Duration,
			"bytes", m.Written,
		)
	}
	return http.HandlerFunc(fn)
}
