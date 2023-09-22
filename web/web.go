// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package web embeds static website files that webservers can serve up to clients.
package web

import (
	"embed"
)

//go:generate env NODE_ENV=production npm run build

// Static holds our static web server content.
//
//go:embed index.html static
var Static embed.FS
