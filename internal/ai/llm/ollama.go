package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/m4rvxpn/portex/internal/scanner"
)

const ollamaDefaultURL = "http://localhost:11434"

// OllamaEnricher calls a local Ollama server for port enrichment.
type OllamaEnricher struct {
	baseURL string
	model   string
	client  *http.Client
	enabled bool
}

// NewOllamaEnricher creates an Ollama enricher.
// baseURL defaults to "http://localhost:11434" if empty.
// model must be non-empty (e.g. "llama3", "mistral").
func NewOllamaEnricher(baseURL, model string) *OllamaEnricher {
	if baseURL == "" {
		baseURL = ollamaDefaultURL
	}
	return &OllamaEnricher{
		baseURL: baseURL,
		model:   model,
		client:  &http.Client{},
		enabled: model != "",
	}
}

// ollamaRequest is the /api/generate request body.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// ollamaResponse is the /api/generate response body (non-streaming).
type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Enrich calls the local Ollama server to analyze the given port result.
func (o *OllamaEnricher) Enrich(ctx context.Context, port scanner.PortResult) (*scanner.LLMEnrichment, error) {
	if !o.enabled {
		return nil, nil
	}

	portCtx := PortContextFromResult(port)
	prompt, err := BuildPrompt(portCtx)
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: %w", err)
	}

	reqBody := ollamaRequest{
		Model:  o.model,
		Prompt: prompt,
		Stream: false,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: marshal request: %w", err)
	}

	url := o.baseURL + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: create request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama enrich: server error %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, fmt.Errorf("ollama enrich: unmarshal response: %w", err)
	}

	enrichment, err := ParseResponse(ollamaResp.Response)
	if err != nil {
		return nil, fmt.Errorf("ollama enrich: %w", err)
	}

	return enrichment, nil
}

// IsEnabled returns true if a model name is configured.
func (o *OllamaEnricher) IsEnabled() bool { return o.enabled }
