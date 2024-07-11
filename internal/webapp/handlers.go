package webapp

import (
	"net/http"

	"github.com/RealImage/bifrost"
)

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet.
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	bifrost.StatsForNerds.WritePrometheus(w)
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		next.ServeHTTP(w, r)
	})
}
