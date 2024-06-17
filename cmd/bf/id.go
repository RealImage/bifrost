package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"github.com/urfave/cli/v3"
)

var idCmd = &cli.Command{
	Name:    "identity",
	Aliases: []string{"id"},
	Usage:   "Parses a bifrost UUID from a pem file",
	Flags: []cli.Flag{
		nsFlag,
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		filename := cmd.Args().First()

		var data []byte
		var err error
		switch filename {
		case "", "-":
			data, err = io.ReadAll(os.Stdin)
		default:
			data, err = os.ReadFile(filename)
		}
		if err != nil {
			return err
		}

		id, err := bifrost.ParseIdentity(data)
		if err != nil {
			slog.ErrorContext(ctx, "error parsing id file", "error", err)
			return cli.Exit("Error parsing file", 1)
		}

		if id.Namespace == uuid.Nil && namespace == uuid.Nil {
			return cli.Exit("Namespace is required", 1)
		}

		// Either we got a namespace from the file or the namespace flag is set
		if id.Namespace != uuid.Nil && namespace != uuid.Nil && id.Namespace != namespace {
			slog.ErrorContext(ctx, "namespace mismatch", "file", id.Namespace, "flag", namespace)
			return cli.Exit("Namespace mismatch", 1)
		}

		if namespace != uuid.Nil {
			id.Namespace = namespace
		}

		slog.Debug("using", "namespace", id.Namespace)
		fmt.Println(id.UUID())

		return nil
	},
}
