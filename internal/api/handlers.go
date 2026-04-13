package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/portex"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// ScanEntry holds all state for a single async scan.
type ScanEntry struct {
	status *ScanStatus
	result *scanner.ScanResult
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// ScanStore holds in-progress and completed scans.
type ScanStore struct {
	mu    sync.RWMutex
	scans map[string]*ScanEntry
}

func newScanStore() *ScanStore {
	return &ScanStore{scans: make(map[string]*ScanEntry)}
}

func (s *ScanStore) set(id string, e *ScanEntry) {
	s.mu.Lock()
	s.scans[id] = e
	s.mu.Unlock()
}

func (s *ScanStore) get(id string) (*ScanEntry, bool) {
	s.mu.RLock()
	e, ok := s.scans[id]
	s.mu.RUnlock()
	return e, ok
}

func (s *ScanStore) delete(id string) {
	s.mu.Lock()
	delete(s.scans, id)
	s.mu.Unlock()
}

// Handler holds all HTTP handler dependencies.
type Handler struct {
	store *ScanStore
}

// NewHandler creates a Handler with an empty scan store.
func NewHandler() *Handler {
	return &Handler{store: newScanStore()}
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("write json response")
	}
}

// StartScan handles POST /v1/scan — starts an async scan.
func (h *Handler) StartScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	if len(req.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets is required"})
		return
	}

	scanID := uuid.New().String()
	ports := req.Ports
	if ports == "" {
		ports = "top1000"
	}
	mode := req.Mode
	if mode == "" {
		mode = "syn"
	}
	timing := req.Timing
	if timing == 0 {
		timing = 3
	}

	cfg := config.Defaults()
	cfg.Targets = req.Targets
	cfg.Ports = ports
	cfg.Mode = config.ScanMode(mode)
	cfg.Timing = config.TimingProfile(timing)
	cfg.EnableRL = req.EnableRL
	cfg.EnableLLM = req.EnableLLM
	cfg.PhantomSessionID = req.SessionID
	cfg.PhantomScanID = scanID
	if len(req.OutputFormats) > 0 {
		cfg.OutputFormat = req.OutputFormats
	}

	ctx, cancel := context.WithCancel(context.Background())

	status := &ScanStatus{
		ID:        scanID,
		State:     "running",
		StartedAt: time.Now(),
	}
	result := &scanner.ScanResult{
		ScanID:    scanID,
		SessionID: req.SessionID,
		Targets:   req.Targets,
		StartTime: time.Now(),
	}

	entry := &ScanEntry{
		status: status,
		result: result,
		cancel: cancel,
	}
	h.store.set(scanID, entry)

	// Run scan in background.
	go func() {
		defer cancel()

		s, err := portex.New(cfg)
		if err != nil {
			entry.mu.Lock()
			entry.status.State = "failed"
			entry.status.Error = err.Error()
			entry.status.Duration = time.Since(entry.status.StartedAt).String()
			entry.mu.Unlock()
			log.Error().Err(err).Str("scan_id", scanID).Msg("create scanner")
			return
		}
		defer s.Close() //nolint:errcheck

		resultChan := make(chan scanner.PortResult, 1000)
		if err := s.ScanStream(ctx, resultChan); err != nil {
			entry.mu.Lock()
			entry.status.State = "failed"
			entry.status.Error = err.Error()
			entry.status.Duration = time.Since(entry.status.StartedAt).String()
			entry.mu.Unlock()
			log.Error().Err(err).Str("scan_id", scanID).Msg("start scan stream")
			return
		}

		for pr := range resultChan {
			entry.mu.Lock()
			entry.result.Ports = append(entry.result.Ports, pr)
			entry.result.TotalPorts++
			if pr.State == scanner.StateOpen {
				entry.result.OpenPorts++
				entry.status.OpenPorts++
			}
			entry.mu.Unlock()
		}

		entry.mu.Lock()
		entry.result.EndTime = time.Now()
		if entry.status.State != "cancelled" {
			entry.status.State = "completed"
			entry.status.Progress = 1.0
		}
		entry.status.Duration = time.Since(entry.status.StartedAt).String()
		entry.mu.Unlock()

		log.Info().Str("scan_id", scanID).Msg("scan completed")
	}()

	writeJSON(w, http.StatusAccepted, ScanResponse{
		ScanID: scanID,
		Status: status,
	})
}

// GetScanStatus handles GET /v1/scan/{id} — returns scan status.
func (h *Handler) GetScanStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entry, ok := h.store.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	entry.mu.RLock()
	status := *entry.status
	entry.mu.RUnlock()

	writeJSON(w, http.StatusOK, status)
}

// GetScanResults handles GET /v1/scan/{id}/results — returns port results as JSON array.
func (h *Handler) GetScanResults(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entry, ok := h.store.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	entry.mu.RLock()
	result := entry.result
	entry.mu.RUnlock()

	writeJSON(w, http.StatusOK, result)
}

// CancelScan handles DELETE /v1/scan/{id} — cancels a running scan.
func (h *Handler) CancelScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entry, ok := h.store.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	entry.mu.Lock()
	if entry.status.State == "running" {
		entry.cancel()
		entry.status.State = "cancelled"
		entry.status.Duration = time.Since(entry.status.StartedAt).String()
	}
	entry.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled", "id": id})
}

// Health handles GET /v1/health — liveness probe.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
