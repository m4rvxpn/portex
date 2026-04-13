package llm

import (
	"fmt"
	"strings"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// GenerateNucleiTemplate generates a basic nuclei YAML template for an open port.
// Uses the service/version information from the scan result; no LLM call is made.
func GenerateNucleiTemplate(port scanner.PortResult) string {
	service := "unknown"
	version := ""
	serviceKeyword := service

	if port.Service != nil {
		if port.Service.Service != "" {
			service = port.Service.Service
			serviceKeyword = service
		}
		if port.Service.Version != "" {
			version = port.Service.Version
		}
	}

	// Build a safe template ID: lowercase, replace spaces/slashes with dashes.
	templateID := fmt.Sprintf("portex-%s-%d",
		sanitizeID(service),
		port.Port,
	)

	// Build the name line.
	nameStr := service
	if version != "" {
		nameStr = fmt.Sprintf("%s %s", service, version)
	}

	tmpl := fmt.Sprintf(`id: %s
info:
  name: "Portex: %s on port %d"
  severity: info
  tags: portex,auto-generated
tcp:
  - inputs:
      - data: ""
    host:
      - "{{Hostname}}"
    port: "%d"
    read-size: 1024
    matchers:
      - type: word
        words:
          - "%s"
`,
		templateID,
		nameStr,
		port.Port,
		port.Port,
		serviceKeyword,
	)

	return strings.TrimRight(tmpl, "\n")
}

// sanitizeID converts a service name to a nuclei-safe template ID segment.
func sanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
