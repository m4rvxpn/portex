// Package api implements the Portex REST API server.
package api

import "time"

// ScanRequest is the POST /v1/scan request body.
type ScanRequest struct {
	Targets       []string `json:"targets"`
	Ports         string   `json:"ports"`
	Mode          string   `json:"mode"`
	EnableRL      bool     `json:"enable_rl"`
	EnableLLM     bool     `json:"enable_llm"`
	OutputFormats []string `json:"output_formats"`
	SessionID     string   `json:"session_id,omitempty"`
	Timing        int      `json:"timing"`
}

// ScanStatus is the current state of an async scan.
type ScanStatus struct {
	ID        string    `json:"id"`
	State     string    `json:"state"` // running|completed|failed|cancelled
	Progress  float64   `json:"progress"`
	OpenPorts int       `json:"open_ports"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// ScanResponse is returned from POST /v1/scan.
type ScanResponse struct {
	ScanID string      `json:"scan_id"`
	Status *ScanStatus `json:"status"`
}
