// Command portex is the Portex port scanner CLI.
package main

import (
	"os"

	"github.com/m4rvxpn/portex/internal/cli"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	root := cli.NewRootCmd(Version)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
