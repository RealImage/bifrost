package sundry

import (
	"context"
	"os"

	"golang.org/x/exp/slog"
)

func OnErrorExit(ctx context.Context, err error, msg string) {
	if err != nil {
		slog.ErrorCtx(ctx, msg, "err", err)
		os.Exit(1)
	}
}
