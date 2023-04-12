// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package stats

import (
	"net/http"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"golang.org/x/exp/slog"
)

// ForNerds captures metrics from various bifrost processes
var ForNerds = metrics.NewSet()

// MaybePushMetrics pushes metrics to url if url is not empty.
// If interval is zero, a one minute interval is used
// Panics if there is an error pushing metrics.
func MaybePushMetrics(url string, interval time.Duration) {
	if url == "" {
		return
	}
	if interval == 0 {
		interval = time.Minute
	}
	slog.Info("pushing metrics", "url", url, "interval", interval)
	if err := ForNerds.InitPush(url, interval, ""); err != nil {
		panic(err)
	}
}

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	ForNerds.WritePrometheus(w)
}
