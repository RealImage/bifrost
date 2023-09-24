// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

const EnvPrefix = "BF"

var (
	BuildRevision string
	BuildTime     time.Time

	// Global program log level.
	LogLevel = new(slog.LevelVar)

	defaultSpec = struct {
		LogLevel  slog.Level `envconfig:"LOG_LEVEL" default:"info"`
		LogSource bool       `envconfig:"LOG_SOURCE" default:"false"`
	}{}

	Bouncer bouncer
	Issuer  issuer
)

func init() {
	BuildRevision, BuildTime = buildInfo()
	envconfig.MustProcess(EnvPrefix, &defaultSpec)
	LogLevel.Set(defaultSpec.LogLevel)

	// Configure JSON logging using the global level.
	opts := &slog.HandlerOptions{AddSource: defaultSpec.LogSource, Level: LogLevel}
	h := slog.NewJSONHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(h))
}

// buildInfo returns build information embedded inside the binary.
func buildInfo() (rev string, t time.Time) {
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

type bouncer struct {
	Host   string `envconfig:"HOST" default:"localhost"`
	Port   int    `envconfig:"PORT" default:"8443"`
	CrtUri string `envconfig:"CRT"  default:"crt.pem"`
	KeyUri string `envconfig:"KEY"  default:"key.pem"`

	BackendUrl    string `envconfig:"BACKEND"       default:"http://localhost:8080"`
	MetricsUrl    string `envconfig:"METRICS"       default:"localhost:9091"`
	SSLKeyLogFile string `envconfig:"SSLKEYLOGFILE"`
}

type issuer struct {
	Host   string `envconfig:"HOST" default:"localhost"`
	Port   int    `envconfig:"PORT" default:"8888"`
	CrtUri string `envconfig:"CRT"  default:"crt.pem"`
	KeyUri string `envconfig:"KEY"  default:"key.pem"`

	Validity time.Duration `envconfig:"VALIDITY" default:"1h"`
	Web      web           `envconfig:"WEB"      default:"false"`
	Metrics  bool          `envconfig:"METRICS"  default:"false"`
}

type web struct {
	Serve      bool
	LocalFiles bool
}

func (w *web) Decode(value string) error {
	if value == "dev" {
		w.Serve = true
		w.LocalFiles = true
		return nil
	}
	if enable, err := strconv.ParseBool(value); err != nil {
		return err
	} else {
		w.Serve = enable
	}
	return nil
}
