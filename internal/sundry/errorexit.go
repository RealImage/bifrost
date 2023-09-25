// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sundry

import (
	"context"
	"os"

	"golang.org/x/exp/slog"
)

// OnErrorExit logs the error and exits with status 1.
func OnErrorExit(ctx context.Context, err error, msg string) {
	if err != nil {
		slog.ErrorCtx(ctx, msg, "err", err)
		os.Exit(1)
	}
}
