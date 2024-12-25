// Package bifrost contains an API client for the Bifrost CA service.
package bifrost

import (
	"context"
	"log/slog"
	"sync/atomic"
)

var (
	// LogLevel is the log level used by the bifrost logger.
	LogLevel = new(slog.LevelVar)

	logger atomic.Pointer[slog.Logger]
)

// Logger returns the global Bifrost logger.
func Logger() *slog.Logger {
	return logger.Load()
}

// SetLogger sets the [*slog.Logger] used by bifrost.
// The default handler disables logging.
func SetLogger(l *slog.Logger) {
	logger.Store(l)
}

func init() {
	SetLogger(slog.New(discardHandler{}))
}

// discardHandler is an [slog.Handler] which is always disabled and therefore logs nothing.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }
