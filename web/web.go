// Package web embeds static website files that webservers can serve up to clients.
// It also includes two `go generate` generators for building Elm application code.
//
// Running `go generate` without any options writes a debug version of the Elm app
// to static/js/main.js. `go generate ./... -skip debug` can be used to produce
// an optimized "production" version.
package web

import (
	"embed"
)

//go:generate -command elmmake elm make src/Main.elm --output=static/js/main.js
//go:generate elmmake --optimize
//go:generate elmmake --debug

// Static holds our static web server content.
//
//go:embed index.html static
var Static embed.FS
