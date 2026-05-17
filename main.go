package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/server"
)

// gitSHA is injected at build time via -ldflags="-X main.gitSHA=...".
var gitSHA = "unknown"

type stdLogger struct{}

func (stdLogger) Errorf(f string, a ...any) { log.Printf("ERROR: "+f, a...) }
func (stdLogger) Infof(f string, a ...any)  { log.Printf("INFO:  "+f, a...) }

func main() {
	addr := envDefault("LISTEN_ADDR", ":8089")
	clerkIssuer := os.Getenv("CLERK_ISSUER")
	clerkAudience := os.Getenv("CLERK_AUDIENCE")
	controlplaneURL := os.Getenv("CONTROLPLANE_URL")
	if env := os.Getenv("GIT_SHA"); env != "" {
		gitSHA = env
	}

	if clerkIssuer == "" {
		log.Fatal("CLERK_ISSUER is required")
	}
	if controlplaneURL == "" {
		log.Fatal("CONTROLPLANE_URL is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	verifier, err := auth.NewVerifier(ctx, auth.Config{
		Issuer:              clerkIssuer,
		Audience:            clerkAudience,
		JWKSRefreshInterval: time.Hour,
		HTTPClient:          &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		log.Fatalf("init verifier: %v", err)
	}

	cpClient := controlplane.NewClient(controlplaneURL, &http.Client{
		Timeout: 30 * time.Second,
	})

	bucketsClient := buckets.NewClient(
		os.Getenv("BUCKETS_URL"),
		os.Getenv("BUCKETS_API_KEY"),
		&http.Client{Timeout: 60 * time.Second},
	)
	if !bucketsClient.Configured() {
		log.Printf("WARN: buckets backend not configured (BUCKETS_URL / BUCKETS_API_KEY); attachment endpoints will return 503")
	}

	deps := server.Deps{Controlplane: cpClient, Buckets: bucketsClient, GitSHA: gitSHA}
	handler := server.NewHandler(deps, verifier, stdLogger{})

	// WriteTimeout is sized for /v1/blobs/migrate-all, which drains
	// every legacy blob scope under a wall-clock budget capped to
	// server.MigrateAllBudget (10m). An 11-minute server WriteTimeout
	// gives the handler 60s of margin to finalize its response. All
	// other routes complete in well under a second; ReadHeaderTimeout
	// stays strict so slowloris cannot exploit the longer write side.
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		log.Printf("sync-enclave listening on %s (git=%s)", addr, gitSHA)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutdown signal received")

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer sCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
