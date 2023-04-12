// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const Prefix = "BF"

// Spec configures a bifrost server.
type Spec struct {
	LogLevel  slog.Level `envconfig:"LOG_LEVEL" default:"info"`
	Address   string     `envconfig:"ADDR"      default:"127.0.0.1:8080"`
	CrtUri    string     `envconfig:"CRT"       default:"crt.pem"`
	KeyUri    string     `envconfig:"KEY"       default:"key.pem"`
	Namespace uuid.UUID  `envconfig:"NS"        default:"1512daa4-ddc1-41d1-8673-3fd19d2f338d"`
}
