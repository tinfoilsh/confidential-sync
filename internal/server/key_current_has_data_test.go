package server

import (
	"context"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
)

// With no registered key, KeyCurrent must surface the null-key shape
// with has_data forwarded from the controlplane so the client can tell
// a legacy user (un-migrated data) apart from a brand-new user.
func TestKeyCurrentForwardsHasDataForLegacyUser(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.cp.mu.Lock()
	f.cp.noKeyHasData = true
	f.cp.mu.Unlock()

	sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
	resp, err := KeyCurrent(context.Background(), f.handler.deps, sess, KeyCurrentRequest{})
	if err != nil {
		t.Fatalf("KeyCurrent returned error: %v", err)
	}
	if resp.KeyID != nil {
		t.Fatalf("expected null key_id, got %q", *resp.KeyID)
	}
	if !resp.HasData {
		t.Fatal("expected has_data=true for a legacy user with un-migrated data")
	}
	if len(resp.Bundles) != 0 {
		t.Fatalf("expected no bundles, got %d", len(resp.Bundles))
	}
}

// A brand-new user (controlplane answers the no-key case) yields the
// same null-key shape but has_data=false so the client offers
// first-time setup.
func TestKeyCurrentNoKeyNoData(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
	resp, err := KeyCurrent(context.Background(), f.handler.deps, sess, KeyCurrentRequest{})
	if err != nil {
		t.Fatalf("KeyCurrent returned error: %v", err)
	}
	if resp.KeyID != nil {
		t.Fatalf("expected null key_id, got %q", *resp.KeyID)
	}
	if resp.HasData {
		t.Fatal("expected has_data=false for a brand-new user")
	}
}
