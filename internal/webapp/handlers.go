// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package webapp

import (
	"net/http"

	"github.com/RealImage/bifrost/web"
	"github.com/google/uuid"
)

// AddRoutes adds web routes to the given mux.
func AddRoutes(mux *http.ServeMux, ns uuid.UUID) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			Index(ns)(w, r)
			return
		}
		http.FileServer(http.FS(web.Static)).ServeHTTP(w, r)
	})
}

// Index returns a handler for the index page.
func Index(ns uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderNameContentType, MimeTypeHtmlCharset)
		data := map[string]any{"ns": ns.String()}
		if err := web.Templates.ExecuteTemplate(w, "index.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
