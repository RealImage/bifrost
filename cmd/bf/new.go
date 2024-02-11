package main

import "github.com/urfave/cli/v2"

var newCmd = &cli.Command{
	Name:    "new",
	Aliases: []string{"n"},
	Usage:   "Create a new Bifrost namespace, identity, or certificate authority",
	Subcommands: []*cli.Command{
		{
			Name:    "namespace",
			Aliases: []string{"ns"},
			Usage:   "Create a new namespace",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:    "identity",
			Aliases: []string{"id"},
			Usage:   "Create a new identity",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:    "certificate-authority",
			Aliases: []string{"ca"},
			Usage:   "Create a new certificate authority",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
}
