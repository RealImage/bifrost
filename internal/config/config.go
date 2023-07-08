// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"os"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const EnvPrefix = "BF"

var (
	Bouncer bouncer
	Issuer  issuer

	// Global program log level.
	LogLevel = new(slog.LevelVar)
)

func init() {
	// Configure JSON logging using the global level.
	opts := &slog.HandlerOptions{Level: LogLevel}
	h := slog.NewJSONHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(h))
}

// CommitInfo returns build information embedded inside the binary.
func CommitInfo() (rev string, t time.Time) {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				rev = s.Value
			} else if s.Key == "vcs.time" {
				if t2, err := time.Parse(time.RFC3339, s.Value); err == nil {
					t = t2
				}
			}
			if rev != "" && !t.IsZero() {
				break
			}
		}
	}
	return
}

type Spec struct {
	LogLevel  slog.Level `envconfig:"LOG_LEVEL" default:"info"`
	Namespace uuid.UUID  `envconfig:"NS"        default:"1512daa4-ddc1-41d1-8673-3fd19d2f338d"`
	Address   string     `envconfig:"ADDR"      default:"127.0.0.1:8080"`
	CrtUri    string     `envconfig:"CRT"       default:"crt.pem"`
	KeyUri    string     `envconfig:"KEY"       default:"key.pem"`
}

type bouncer struct {
	Spec
	Address       string `envconfig:"ADDR"    default:"localhost:8443"`
	BackendUrl    string `envconfig:"BACKEND" default:"http://localhost:8080"`
	MetricsUrl    string `envconfig:"METRICS" default:"localhost:9091"`
	SSLKeyLogFile string `envconfig:"SSLKEYLOGFILE"`
}

type issuer struct {
	Spec
	Address       string        `envconfig:"ADDR"      default:"127.0.0.1:8888"`
	IssueDuration time.Duration `envconfig:"ISSUE_DUR" default:"1h"`
}
