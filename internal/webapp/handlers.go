package webapp

import (
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/web"
	"github.com/google/uuid"
)

// AddRoutes adds web routes to the given mux.
// If localStaticFiles is true, the webapp will serve static files from the
// local filesystem. Otherwise, it will serve them from the embedded filesystem.
func AddRoutes(mux *http.ServeMux, staticFilesPath string, ns uuid.UUID) {
	index := Index(ns)
	var static http.Handler
	if staticFilesPath == "embed" {
		static = http.FileServer(http.FS(web.Static))
	} else {
		static = http.FileServer(http.Dir(staticFilesPath))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			index.ServeHTTP(w, r)
		} else {
			static.ServeHTTP(w, r)
		}
	})
}

// Index returns a handler for the index page.
func Index(ns uuid.UUID) http.Handler {
	data := map[string]string{"ns": ns.String()}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderNameContentType, MimeTypeHtmlCharset)
		if err := web.Templates.ExecuteTemplate(w, "index.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	bifrost.StatsForNerds.WritePrometheus(w)
}
