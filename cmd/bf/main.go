package main

import (
	"context"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/urfave/cli/v3"
)

func main() {
	rev, t := getBuildInfo()
	version := rev + " (" + t.String() + ")"

	cli := &cli.Command{
		Name:    "bf",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Sources: cli.EnvVars("LOG_LEVEL"),
				Value:   slog.LevelInfo.String(),
				Action: func(_ context.Context, _ *cli.Command, l string) error {
					logLevel := new(slog.LevelVar)
					if err := logLevel.UnmarshalText([]byte(l)); err != nil {
						return err
					}
					hdlr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
					slog.SetDefault(slog.New(hdlr))
					return nil
				},
			},
		},
		Commands: []*cli.Command{
			caCmd,
			idCmd,
			proxyCmd,
			newCmd,
		},
		DefaultCommand: "certificate-authority",
	}
	if err := cli.Run(context.Background(), os.Args); err != nil {
		panic(err)
	}
}

func getBuildInfo() (rev string, t time.Time) {
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
