package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/m4rvxpn/portex/internal/scanner"
)

const (
	geminiAPIBase      = "https://generativelanguage.googleapis.com/v1beta/models"
	geminiDefaultModel = "gemini-2.0-flash"
	geminiMaxTokens    = 1024
)

// GeminiEnricher calls the Google Gemini API for port enrichment.
type GeminiEnricher struct {
	apiKey  string
	model   string
	client  *http.Client
	enabled bool
}

// NewGeminiEnricher creates a Gemini enricher.
// apiKey: from argument or GEMINI_API_KEY env var (argument takes precedence).
// model: defaults to "gemini-2.0-flash" if empty.
func NewGeminiEnricher(apiKey, model string) *GeminiEnricher {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if model == "" {
		model = geminiDefaultModel
	}
	return &GeminiEnricher{
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{},
		enabled: apiKey != "",
	}
}

// geminiRequest is the Gemini generateContent request body.
type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	GenerationConfig geminiGenerationConfig `json:"generationConfig"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens"`
	Temperature     float64 `json:"temperature"`
}

// geminiResponse is the Gemini generateContent response body (simplified).
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error,omitempty"`
}

// Enrich calls the Gemini API to analyze the given port result.
func (g *GeminiEnricher) Enrich(ctx context.Context, port scanner.PortResult) (*scanner.LLMEnrichment, error) {
	if !g.enabled {
		return nil, nil
	}

	portCtx := PortContextFromResult(port)
	prompt, err := BuildPrompt(portCtx)
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: %w", err)
	}

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: geminiMaxTokens,
			Temperature:     0.2,
		},
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/%s:generateContent?key=%s", geminiAPIBase, g.model, g.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: create request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini enrich: API error %d: %s", resp.StatusCode, string(body))
	}

	var geminiResp geminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, fmt.Errorf("gemini enrich: unmarshal response: %w", err)
	}

	if geminiResp.Error != nil {
		return nil, fmt.Errorf("gemini enrich: API error %d %s: %s",
			geminiResp.Error.Code, geminiResp.Error.Status, geminiResp.Error.Message)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini enrich: empty response")
	}

	text := geminiResp.Candidates[0].Content.Parts[0].Text
	enrichment, err := ParseResponse(text)
	if err != nil {
		return nil, fmt.Errorf("gemini enrich: %w", err)
	}

	return enrichment, nil
}

// IsEnabled returns true if an API key is configured.
func (g *GeminiEnricher) IsEnabled() bool { return g.enabled }
