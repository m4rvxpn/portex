package cli

import (
	"github.com/spf13/cobra"

	"github.com/m4rvxpn/portex/internal/api"
)

// NewServeCmd returns the `portex serve` subcommand that starts the REST API server.
func NewServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Portex REST API server",
		Long:  "Start the REST API server to accept scan requests over HTTP.",
		RunE:  runServe,
	}

	cmd.Flags().String("bind", "0.0.0.0:8080", "address to bind the HTTP listener")
	cmd.Flags().String("api-key", "", "API key for X-API-Key authentication (empty = no auth)")

	return cmd
}

// runServe is the cobra RunE handler for the serve command.
func runServe(cmd *cobra.Command, _ []string) error {
	bind, _ := cmd.Flags().GetString("bind")
	apiKey, _ := cmd.Flags().GetString("api-key")

	srv := api.NewServer(bind, apiKey)
	return srv.Start(cmd.Context())
}
