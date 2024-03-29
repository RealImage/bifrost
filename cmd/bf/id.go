package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

var idCmd = &cli.Command{
	Name:    "identity",
	Aliases: []string{"id"},
	Flags: []cli.Flag{
		nsFlag,
	},
	Action: func(cliCtx *cli.Context) error {
		filename := cliCtx.Args().First()

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
			return cli.Exit(fmt.Sprintf("Error parsing file: %s", err), 1)
		}

		if id.Namespace == uuid.Nil && namespace == uuid.Nil {
			return cli.Exit("Error: Namespace is required", 1)
		}
		if id.Namespace != uuid.Nil && namespace != uuid.Nil && id.Namespace != namespace {
			return cli.Exit("Error: Namespace mismatch", 1)
		}
		if namespace != uuid.Nil {
			id.Namespace = namespace
		}

		slog.Debug("using", "namespace", id.Namespace)
		fmt.Println(id.UUID())

		return nil
	},
}
