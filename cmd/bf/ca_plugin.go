//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)

package main

import "github.com/urfave/cli/v3"

func init() {
	caServeCmd.Flags = append(caServeCmd.Flags, &cli.StringFlag{
		Name:        "gauntlet-plugin",
		Aliases:     []string{"g", "plugin"},
		Sources:     cli.EnvVars("GAUNTLET_PLUGIN"),
		Usage:       "path to a gauntlet plugin file",
		Destination: &gauntletPlugin,
	})
}
