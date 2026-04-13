package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// PortContext is the structured input for LLM prompts.
type PortContext struct {
	IP       string
	Port     int
	Protocol string
	Service  string
	Version  string
	Banner   string
	OS       string
	CPE      string
}

// PortContextFromResult builds a PortContext from a PortResult.
func PortContextFromResult(r scanner.PortResult) PortContext {
	ctx := PortContext{
		IP:       r.Target,
		Port:     r.Port,
		Protocol: r.Protocol,
	}
	if r.Service != nil {
		ctx.Service = r.Service.Service
		ctx.Version = r.Service.Version
		ctx.Banner = r.Service.Banner
		ctx.CPE = r.Service.CPE
	}
	if r.OS != nil {
		ctx.OS = r.OS.Name
	}
	return ctx
}

const enrichPromptTemplate = `You are a security analyst. Analyze this open network port and provide:
1. A brief summary of what service is likely running
2. Known CVEs for this service/version (list up to 5)
3. Specific exploitation hints for penetration testers
4. Confidence score (0.0-1.0)

Port: {{.Port}}/{{.Protocol}}
Service: {{.Service}} {{.Version}}
Banner: {{.Banner}}
OS: {{.OS}}
CPE: {{.CPE}}

Respond in JSON format:
{
  "summary": "...",
  "cves": ["CVE-XXXX-XXXX"],
  "exploit_hints": ["..."],
  "confidence": 0.85
}`

var promptTmpl = template.Must(template.New("enrich").Parse(enrichPromptTemplate))

// BuildPrompt renders the prompt template for the given port context.
func BuildPrompt(ctx PortContext) (string, error) {
	var buf bytes.Buffer
	if err := promptTmpl.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("prompt render: %w", err)
	}
	return buf.String(), nil
}

// llmResponse is the expected JSON shape from the LLM.
type llmResponse struct {
	Summary      string   `json:"summary"`
	CVEs         []string `json:"cves"`
	ExploitHints []string `json:"exploit_hints"`
	Confidence   float64  `json:"confidence"`
}

// ParseResponse parses the LLM JSON response into a LLMEnrichment struct.
// It extracts the JSON object from the response even if it contains surrounding text.
func ParseResponse(response string) (*scanner.LLMEnrichment, error) {
	// Find the JSON block — the model may wrap it in prose.
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("parse response: no JSON object found in response")
	}
	jsonStr := response[start : end+1]

	var resp llmResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &scanner.LLMEnrichment{
		Summary:      resp.Summary,
		CVEs:         resp.CVEs,
		ExploitHints: resp.ExploitHints,
		Confidence:   resp.Confidence,
	}, nil
}
