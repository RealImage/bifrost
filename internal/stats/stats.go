// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package stats

import (
	"net/http"

	"github.com/VictoriaMetrics/metrics"
)

// ForNerds captures metrics from various bifrost processes
var ForNerds = metrics.NewSet()

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	ForNerds.WritePrometheus(w)
}
