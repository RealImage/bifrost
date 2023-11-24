// Package web embeds static website files that webservers can serve up to clients.
package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:generate npm run build

var (
	//go:embed static
	static embed.FS

	//go:embed templates
	templates embed.FS

	// Static is the embedded filesystem containing the static website files.
	Static fs.FS

	// Templates is the parsed HTML templates.
	Templates *template.Template
)

func init() {
	var err error
	if Static, err = fs.Sub(static, "static"); err != nil {
		panic("error embedding static files: " + err.Error())
	}

	Templates = template.Must(template.ParseFS(templates, "templates/*.html"))
}
