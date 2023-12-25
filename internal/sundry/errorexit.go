package sundry

import (
	"context"
	"log/slog"
	"os"
)

// OnErrorExit logs the error and exits with status 1.
func OnErrorExit(ctx context.Context, err error, msg string) {
	if err != nil {
		slog.ErrorContext(ctx, msg, "error", err)
		os.Exit(1)
	}
}
