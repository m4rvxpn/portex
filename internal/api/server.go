package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// Server is the Portex REST API server.
type Server struct {
	bind   string
	apiKey string
	router *chi.Mux
	srv    *http.Server
}

// NewServer creates a Server bound to the given address with optional API key auth.
func NewServer(bind, apiKey string) *Server {
	s := &Server{
		bind:   bind,
		apiKey: apiKey,
		router: chi.NewRouter(),
	}
	s.setupRoutes()
	return s
}

// setupRoutes configures all API routes and middleware.
func (s *Server) setupRoutes() {
	h := NewHandler()

	s.router.Use(chimw.Recoverer)
	s.router.Use(LoggingMiddleware)
	s.router.Use(APIKeyMiddleware(s.apiKey))

	s.router.Post("/v1/scan", h.StartScan)
	s.router.Get("/v1/scan/{id}", h.GetScanStatus)
	s.router.Get("/v1/scan/{id}/results", h.GetScanResults)
	s.router.Delete("/v1/scan/{id}", h.CancelScan)
	s.router.Get("/v1/health", h.Health)
}

// Start begins listening for HTTP requests. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.srv = &http.Server{
		Addr:    s.bind,
		Handler: s.router,
	}

	// Shutdown gracefully when ctx is cancelled.
	go func() {
		<-ctx.Done()
		if err := s.srv.Shutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("api server shutdown")
		}
	}()

	log.Info().Str("bind", s.bind).Msg("portex api server starting")
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
