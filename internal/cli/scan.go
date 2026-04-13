package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/output"
	"github.com/m4rvxpn/portex/internal/portex"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// NewScanCmd returns the `portex scan` subcommand.
func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a port scan",
		Long:  "Scan one or more targets using the specified scan mode and output results.",
		RunE:  runScan,
	}

	AddCommonFlags(cmd)

	f := cmd.Flags()
	f.String("mode", "syn", "scan mode: syn, ack, fin, xmas, null, window, maimon, udp, sctp, ipproto, idle, ftp, connect, stealth")
	f.Bool("service-detect", false, "enable service/version detection")
	f.Bool("os-detect", false, "enable OS fingerprinting")
	f.Bool("script-scan", false, "enable NSE-compatible Lua script scan")
	f.String("scripts", "", "comma-separated script names to run")
	f.Bool("rl", false, "enable reinforcement-learning probe adaptation")
	f.Bool("mutate", false, "enable packet-level payload mutation")
	f.Bool("mimic", false, "enable traffic mimicry (browser/app emulation)")
	f.Bool("llm", false, "enable LLM-based enrichment")
	f.String("llm-provider", "claude", "LLM provider: claude or ollama")
	f.String("llm-model", "", "LLM model identifier (provider-specific)")
	f.String("zombie", "", "zombie host:port for idle scan")
	f.String("session-id", "", "Phantom EASM pipeline session ID")

	return cmd
}

// runScan is the cobra RunE handler for the scan command.
func runScan(cmd *cobra.Command, _ []string) error {
	cfg, err := buildConfig(cmd)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}

	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no targets specified: use -t/--targets")
	}

	verbose, _ := cmd.Flags().GetBool("verbose")

	// Build output writers.
	writer, err := buildOutputWriter(cfg)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	defer writer.Close() //nolint:errcheck

	// Create the scanner.
	s, err := portex.New(cfg)
	if err != nil {
		return fmt.Errorf("create scanner: %w", err)
	}
	defer s.Close() //nolint:errcheck

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	resultChan := make(chan scanner.PortResult, 1000)
	if err := s.ScanStream(ctx, resultChan); err != nil {
		return fmt.Errorf("start scan: %w", err)
	}

	result := &scanner.ScanResult{
		ScanID:    cfg.PhantomScanID,
		SessionID: cfg.PhantomSessionID,
		Targets:   cfg.Targets,
	}

	for r := range resultChan {
		if err := writer.WritePort(r); err != nil {
			log.Warn().Err(err).Msg("write port result")
		}
		result.Ports = append(result.Ports, r)
		result.TotalPorts++
		if r.State == scanner.StateOpen {
			result.OpenPorts++
			if verbose {
				log.Info().
					Str("target", r.Target).
					Int("port", r.Port).
					Str("protocol", r.Protocol).
					Str("state", string(r.State)).
					Str("reason", r.Reason).
					Msg("open port")
			}
		}
	}

	if err := writer.WriteResult(result); err != nil {
		log.Warn().Err(err).Msg("write final result")
	}

	fmt.Fprintf(os.Stderr, "\nScan complete: %d total ports, %d open\n",
		result.TotalPorts, result.OpenPorts)

	return nil
}

// buildConfig constructs a *config.Config from cobra flag values.
func buildConfig(cmd *cobra.Command) (*config.Config, error) {
	cfg := config.Defaults()

	targetsRaw, _ := cmd.Flags().GetString("targets")
	if targetsRaw != "" {
		cfg.Targets = splitComma(targetsRaw)
	}

	cfg.Ports, _ = cmd.Flags().GetString("ports")

	timing, _ := cmd.Flags().GetInt("timing")
	cfg.Timing = config.TimingProfile(timing)

	goroutines, _ := cmd.Flags().GetInt("goroutines")
	cfg.Goroutines = goroutines

	outputFmt, _ := cmd.Flags().GetString("output")
	cfg.OutputFormat = splitComma(outputFmt)

	cfg.OutputFile, _ = cmd.Flags().GetString("output-file")
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")

	proxyURL, _ := cmd.Flags().GetString("proxy")
	if proxyURL != "" {
		cfg.ProxyAddr = proxyURL
		cfg.UseProxy = true
	}

	// Scan-specific flags (only present on the scan command).
	if f := cmd.Flags().Lookup("mode"); f != nil {
		mode, _ := cmd.Flags().GetString("mode")
		cfg.Mode = config.ScanMode(mode)
	}
	if f := cmd.Flags().Lookup("service-detect"); f != nil {
		cfg.ServiceDetect, _ = cmd.Flags().GetBool("service-detect")
	}
	if f := cmd.Flags().Lookup("os-detect"); f != nil {
		cfg.OSDetect, _ = cmd.Flags().GetBool("os-detect")
	}
	if f := cmd.Flags().Lookup("script-scan"); f != nil {
		cfg.ScriptScan, _ = cmd.Flags().GetBool("script-scan")
	}
	if f := cmd.Flags().Lookup("scripts"); f != nil {
		scripts, _ := cmd.Flags().GetString("scripts")
		if scripts != "" {
			cfg.Scripts = splitComma(scripts)
		}
	}
	if f := cmd.Flags().Lookup("rl"); f != nil {
		cfg.EnableRL, _ = cmd.Flags().GetBool("rl")
	}
	if f := cmd.Flags().Lookup("mutate"); f != nil {
		cfg.EnableMutator, _ = cmd.Flags().GetBool("mutate")
	}
	if f := cmd.Flags().Lookup("mimic"); f != nil {
		cfg.EnableMimicry, _ = cmd.Flags().GetBool("mimic")
	}
	if f := cmd.Flags().Lookup("llm"); f != nil {
		cfg.EnableLLM, _ = cmd.Flags().GetBool("llm")
	}
	if f := cmd.Flags().Lookup("llm-provider"); f != nil {
		cfg.LLMProvider, _ = cmd.Flags().GetString("llm-provider")
	}
	if f := cmd.Flags().Lookup("llm-model"); f != nil {
		cfg.LLMModel, _ = cmd.Flags().GetString("llm-model")
	}
	if f := cmd.Flags().Lookup("zombie"); f != nil {
		zombie, _ := cmd.Flags().GetString("zombie")
		if zombie != "" {
			parts := strings.SplitN(zombie, ":", 2)
			cfg.ZombieHost = parts[0]
			if len(parts) == 2 {
				port := 0
				fmt.Sscanf(parts[1], "%d", &port)
				cfg.ZombiePort = port
			}
		}
	}
	if f := cmd.Flags().Lookup("session-id"); f != nil {
		cfg.PhantomSessionID, _ = cmd.Flags().GetString("session-id")
	}

	return cfg, cfg.Validate()
}

// buildOutputWriter constructs the appropriate Writer(s) from config.
func buildOutputWriter(cfg *config.Config) (output.Writer, error) {
	if len(cfg.OutputFormat) == 0 {
		cfg.OutputFormat = []string{"json"}
	}

	if len(cfg.OutputFormat) == 1 {
		dest, closer, err := openOutput(cfg.OutputFile, cfg.OutputFormat[0])
		if err != nil {
			return nil, err
		}
		_ = closer
		w, err := output.NewWriter(cfg.OutputFormat[0], dest, cfg.PhantomScanID)
		if err != nil {
			return nil, err
		}
		return w, nil
	}

	// Multiple formats.
	var writers []output.Writer
	for _, fmt := range cfg.OutputFormat {
		dest, _, err := openOutput(cfg.OutputFile, fmt)
		if err != nil {
			return nil, err
		}
		w, err := output.NewWriter(fmt, dest, cfg.PhantomScanID)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}
	return output.NewMultiWriter(writers...), nil
}

// openOutput returns an io.Writer for the given format and base path.
// For nuclei-yaml the writer string is the directory path.
func openOutput(base, format string) (io.Writer, func(), error) {
	if base == "" || format == "nuclei-yaml" {
		return os.Stdout, func() {}, nil
	}

	suffix := "." + format
	if format == "bbot" {
		suffix = ".ndjson"
	} else if format == "xml" {
		suffix = ".xml"
	}

	path := base + suffix
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file %q: %w", path, err)
	}
	return f, func() { f.Close() }, nil
}

// splitComma splits a comma-separated string, trimming whitespace.
func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
