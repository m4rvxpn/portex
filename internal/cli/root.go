package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const banner = `
 ____  ___  ____  ____  ____ _  _
(  _ \/ __)(  _ \(_  _)(  __)( \/ )
 ) __/ (_ \ )   / _)(_  ) _)  )  (
(__)  \___/(__\_)(____)(____) (__/

  Portex — AI-augmented port scanner
`

// NewRootCmd returns the root cobra command for Portex.
func NewRootCmd(version string) *cobra.Command {
	var verbose bool

	root := &cobra.Command{
		Use:     "portex",
		Short:   "Portex — AI-augmented port scanner",
		Long:    banner,
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			// Skip banner for completion helpers.
			if cmd.Name() == "__complete" || cmd.Name() == "__completeNoDesc" {
				return
			}
			fmt.Fprint(os.Stderr, banner)

			// Configure zerolog.
			level := zerolog.InfoLevel
			if verbose {
				level = zerolog.DebugLevel
			}
			zerolog.SetGlobalLevel(level)
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		},
	}

	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose/debug logging")

	root.AddCommand(NewScanCmd())
	root.AddCommand(NewServeCmd())

	return root
}
