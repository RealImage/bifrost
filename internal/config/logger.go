// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"os"

	"golang.org/x/exp/slog"
)

func Log(level slog.Level) {
	handler := slog.HandlerOptions{Level: level}.NewJSONHandler(os.Stderr)
	slog.SetDefault(slog.New(handler))
}
