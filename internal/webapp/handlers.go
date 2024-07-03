package webapp

import (
	"net/http"

	"github.com/RealImage/bifrost"
)

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet.
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	bifrost.StatsForNerds.WritePrometheus(w)
}
