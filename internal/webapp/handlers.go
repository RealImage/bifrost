package webapp

import (
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/web"
	"github.com/google/uuid"
)

// AddRoutes adds the webapp routes to the provided ServeMux.
// The staticFilesPath can be a directory path or "embed" to use the embedded static files.
// The webapp HTTP handlers are:
// - GET /namespace.js: returns the namespace as a JavaScript module.
// - GET /: returns the index page.
// - GET /*: returns static files.
func AddRoutes(mux *http.ServeMux, staticFilesPath string, ns uuid.UUID) {
	index := Index(ns)
	var static http.Handler
	if staticFilesPath == "embed" {
		static = http.FileServer(http.FS(web.Static))
	} else {
		static = http.FileServer(http.Dir(staticFilesPath))
	}

	nsJS := "export default '" + ns.String() + "';"
	mux.HandleFunc("GET /namespace.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderNameContentType, MimeTypeJavascript)
		if _, err := w.Write([]byte(nsJS)); err != nil {
			slog.Error("error writing namespace.js", "error", err)
		}
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
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

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet.
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	bifrost.StatsForNerds.WritePrometheus(w)
}
