// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

const (
	EnvPrefix = "BF"

	StaticFilesEmbedded = "embedded"
)

var (
	BuildRevision string
	BuildTime     time.Time

	// Global program log level.
	LogLevel = new(slog.LevelVar)

	defaultSpec = struct {
		LogLevel  slog.Level `envconfig:"LOG_LEVEL" default:"info"`
		LogSource bool       `envconfig:"LOG_SOURCE" default:"false"`
	}{}

	Bouncer  bouncer
	HallPass hallpass
	Issuer   issuer
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
	Namespace uuid.UUID `envconfig:"NAMESPACE" required:"true"`
}

type Server struct {
	Host            string        `envconfig:"HOST"             default:"localhost"`
	CrtUri          string        `envconfig:"CRT"              default:"crt.pem"`
	KeyUri          string        `envconfig:"KEY"              default:"key.pem"`
	ShutdownTimeout time.Duration `envconfig:"SHUTDOWN_TIMEOUT" default:"2s"`
}

type hallpass struct {
	Server
	Port          int    `envconfig:"PORT"          default:"8443"`
	BackendUrl    string `envconfig:"BACKEND"       default:"http://localhost:8080"`
	MetricsUrl    string `envconfig:"METRICS"       default:"localhost:9091"`
	SSLKeyLogFile string `envconfig:"SSLKEYLOGFILE"`
}

type issuer struct {
	Server
	Port     int           `envconfig:"PORT"     default:"8888"`
	Validity time.Duration `envconfig:"VALIDITY" default:"1h"`
	Web      web           `envconfig:"WEB"      default:"false"`
	Metrics  bool          `envconfig:"METRICS"  default:"false"`
}

type web struct {
	Enabled         bool
	StaticFilesPath string
}

// Decode implements envconfig.Decoder.
// It decodes a boolean or a directory path.
func (w *web) Decode(value string) error {
	value = strings.TrimPrefix(value, "file://")
	si, err := os.Stat(value)
	if err != nil || !si.IsDir() {
		if berr := w.decodeBool(value); berr != nil {
			err := errors.Join(err, berr)
			return fmt.Errorf("%s is not a directory or a boolean: %w", value, err)
		}
		return nil
	}

	if err == nil && si.IsDir() {
		w.Enabled = true
		w.StaticFilesPath = value
		return nil
	}

	if err := w.decodeBool(value); err != nil {
		return fmt.Errorf("%s is not a directory or a boolean: %w", value, err)
	}
	return nil
}

func (w *web) decodeBool(value string) error {
	en, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("invalid value %q for web: %w", value, err)
	}
	w.Enabled = en
	w.StaticFilesPath = StaticFilesEmbedded
	return nil
}
