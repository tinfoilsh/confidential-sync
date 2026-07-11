package server

import (
	"context"
	"testing"
)

func TestSearchInferenceRateDenialRestoresUserBudget(t *testing.T) {
	gate := newSearchInferenceGate(searchInferenceLimits{
		globalRate:       0,
		globalBurst:      1,
		globalConcurrent: 1,
		userRate:         0,
		userBurst:        1,
		userConcurrent:   1,
	})

	release, err := gate.acquire(context.Background(), "winner", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	release()

	if _, err := gate.acquire(context.Background(), "denied", 1, false); err == nil {
		t.Fatal("expected global rate denial")
	}
	gate.mu.Lock()
	denied := gate.users["denied"]
	gate.mu.Unlock()
	if tokens := denied.foreground.Tokens(); tokens != 1 {
		t.Fatalf("denied user tokens = %v, want 1", tokens)
	}
}
