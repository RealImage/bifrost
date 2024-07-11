package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/RealImage/bifrost"
	"github.com/urfave/cli/v3"
)

var revision = "unknown"

func main() {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
				break
			}
		}
	}

	logLevel := new(slog.LevelVar)
	hdlr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(hdlr))

	cli := &cli.Command{
		Name:    "bifrost",
		Aliases: []string{"bf"},
		Version: fmt.Sprintf("%s (%s)", bifrost.Version, revision),
		Usage:   "Bifrost is an mTLS Certificate Authority and Identity Proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Sources: cli.EnvVars("LOG_LEVEL"),
				Value:   slog.LevelInfo.String(),
				Action: func(_ context.Context, _ *cli.Command, level string) error {
					return logLevel.UnmarshalText([]byte(level))
				},
			},
		},
		Commands: []*cli.Command{
			caServeCmd,
			caIssueCmd,
			requestCmd,
			idCmd,
			proxyCmd,
			newCmd,
		},
		DefaultCommand: "serve",
	}

	if err := cli.Run(context.Background(), os.Args); err != nil {
		panic(err)
	}
}
