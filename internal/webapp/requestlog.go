package webapp

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/felixge/httpsnoop"
)

// RequestLogger logs the request method and uri to stdout.
func RequestLogger(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(h, w, r)

		level := slog.LevelInfo

		if m.Code >= 400 && m.Code < 500 {
			level = slog.LevelWarn
		} else if m.Code >= 500 {
			level = slog.LevelError
		}

		bifrost.Logger().LogAttrs(
			r.Context(),
			level,
			fmt.Sprintf("%s %s", r.Method, r.RequestURI),
			slog.String("method", r.Method),
			slog.String("uri", r.RequestURI),
			slog.Int("status", m.Code),
			slog.Duration("duration", m.Duration),
			slog.Int64("bytes", m.Written),
		)
	}

	return http.HandlerFunc(fn)
}
