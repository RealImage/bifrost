package config

import (
	"os"

	"golang.org/x/exp/slog"
)

func Log(level slog.Level) {
	handler := slog.HandlerOptions{Level: level}.NewJSONHandler(os.Stderr)
	slog.SetDefault(slog.New(handler))
}
