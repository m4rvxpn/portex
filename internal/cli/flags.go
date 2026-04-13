// Package cli implements the Portex command-line interface using cobra.
package cli

import "github.com/spf13/cobra"

// AddCommonFlags adds the flags shared by all scan-related subcommands.
func AddCommonFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.StringP("targets", "t", "", "target IPs, CIDRs, or hostnames (comma-separated)")
	f.StringP("ports", "p", "top1000", "port specification: e.g. 80,443, 1-1024, top100, top1000, all")
	f.Int("timing", 3, "timing profile T0–T5 (0=paranoid, 5=insane)")
	f.Int("goroutines", 5000, "maximum concurrency (goroutines)")
	f.String("output", "json", "comma-separated output formats: json,bbot,xml,csv,nuclei-yaml")
	f.String("output-file", "", "base path for output files (empty = stdout)")
	f.Bool("verbose", false, "enable verbose logging")
	f.String("proxy", "", "proxy URL, e.g. socks5://127.0.0.1:1080")
}
