package webapp

import (
	"net/http"

	"github.com/RealImage/bifrost/web"
)

func AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			Index(w, r)
			return
		}
		http.FileServer(http.FS(web.Static)).ServeHTTP(w, r)
	})
}

func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = web.Templates.ExecuteTemplate(w, "index.html", nil)
}
