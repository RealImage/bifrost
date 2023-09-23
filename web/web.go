// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package web embeds static website files that webservers can serve up to clients.
package web

import (
	"embed"
	"io/fs"
)

//go:generate env NODE_ENV=production npm run build

var (
	//go:embed static
	static embed.FS

	// Static is the embedded filesystem containing the static website files.
	Static fs.FS
)

func init() {
	var err error
	if Static, err = fs.Sub(static, "static"); err != nil {
		panic("error embedding static files: " + err.Error())
	}
}
