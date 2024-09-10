package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"
)

var version = "devel"

func main() {
	logLevel := new(slog.LevelVar)
	hdlr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(hdlr))

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
