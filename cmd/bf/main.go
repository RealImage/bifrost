package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/urfave/cli/v3"
)

var version = "devel"

func main() {
	logger := slog.New(
		slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: bifrost.LogLevel}),
	)

	slog.SetDefault(logger)
	bifrost.SetLogger(logger)

	cli := &cli.Command{
		Name:    "bifrost",
		Aliases: []string{"bf"},
		Version: version,
		Usage:   "Bifrost is an mTLS Certificate Authority and Identity Proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Sources: cli.EnvVars("LOG_LEVEL"),
				Value:   slog.LevelInfo.String(),
				Action: func(_ context.Context, _ *cli.Command, level string) error {
					return bifrost.LogLevel.UnmarshalText([]byte(level))
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
