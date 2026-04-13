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
	claudeAPIEndpoint   = "https://api.anthropic.com/v1/messages"
	claudeDefaultModel  = "claude-sonnet-4-6"
	claudeAPIVersion    = "2023-06-01"
	claudeMaxTokens     = 1024
)

// ClaudeEnricher calls the Anthropic Claude API for port enrichment.
type ClaudeEnricher struct {
	apiKey  string
	model   string
	client  *http.Client
	enabled bool
}

// NewClaudeEnricher creates a Claude enricher.
// apiKey: from argument or ANTHROPIC_API_KEY env var (argument takes precedence).
// model: defaults to "claude-sonnet-4-6" if empty.
func NewClaudeEnricher(apiKey, model string) *ClaudeEnricher {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if model == "" {
		model = claudeDefaultModel
	}
	return &ClaudeEnricher{
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{},
		enabled: apiKey != "",
	}
}

// claudeRequest is the Anthropic Messages API request body.
type claudeRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	Messages  []claudeMessage  `json:"messages"`
}

// claudeMessage is a single message in the conversation.
type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// claudeResponse is the Anthropic Messages API response body (simplified).
type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Enrich calls the Claude API to analyze the given port result.
func (c *ClaudeEnricher) Enrich(ctx context.Context, port scanner.PortResult) (*scanner.LLMEnrichment, error) {
	if !c.enabled {
		return nil, nil
	}

	portCtx := PortContextFromResult(port)
	prompt, err := BuildPrompt(portCtx)
	if err != nil {
		return nil, fmt.Errorf("claude enrich: %w", err)
	}

	reqBody := claudeRequest{
		Model:     c.model,
		MaxTokens: claudeMaxTokens,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("claude enrich: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, claudeAPIEndpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("claude enrich: create request: %w", err)
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", claudeAPIVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("claude enrich: http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("claude enrich: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claude enrich: API error %d: %s", resp.StatusCode, string(body))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return nil, fmt.Errorf("claude enrich: unmarshal response: %w", err)
	}

	if claudeResp.Error != nil {
		return nil, fmt.Errorf("claude enrich: API error %s: %s", claudeResp.Error.Type, claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("claude enrich: empty response content")
	}

	text := claudeResp.Content[0].Text
	enrichment, err := ParseResponse(text)
	if err != nil {
		return nil, fmt.Errorf("claude enrich: %w", err)
	}

	return enrichment, nil
}

// IsEnabled returns true if an API key is configured.
func (c *ClaudeEnricher) IsEnabled() bool { return c.enabled }
