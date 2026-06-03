//go:build sidecar_integration

package buckets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

// These tests exercise the buckets.Client against a real, running
// tinfoil-buckets-sidecar instead of the in-memory stub. They are
// excluded from the default build and run only under the
// sidecar_integration tag:
//
//	BUCKETS_SIDECAR_URL=http://localhost:9000 \
//	  go test -tags sidecar_integration ./internal/buckets/...
//
// Bring the sidecar up first using the same image the enclave
// colocates, in multitenant mode, backed by an S3 bucket it can reach:
//
//	docker run --rm -p 9000:9000 \
//	  -e PORT=9000 -e MULTITENANT=true \
//	  -e BUCKET=<bucket> -e AWS_REGION=<region> \
//	  -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... \
//	  ghcr.io/tinfoilsh/tinfoil-buckets-sidecar:<tag>
//
// Each test isolates itself under a random per-run owner so it never
// collides with real tenants, and deletes everything it writes.

const sidecarURLEnv = "BUCKETS_SIDECAR_URL"

const integrationTimeout = 30 * time.Second

func newSidecarClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv(sidecarURLEnv)
	if url == "" {
		t.Skipf("set %s to a running multitenant tinfoil-buckets-sidecar to run this test", sidecarURLEnv)
	}
	return NewClient(url, nil)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, encryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return key
}

func randomOwner(t *testing.T) string {
	t.Helper()
	return "itest-" + randomHex(t, 8)
}

func TestSidecarPutGetDeleteRoundTrip(t *testing.T) {
	c := newSidecarClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	owner := randomOwner(t)
	token := randomHex(t, 16)
	key := randomKey(t)
	plaintext := []byte("integration round-trip " + randomHex(t, 4))

	if err := c.Put(ctx, owner, token, plaintext, key); err != nil {
		t.Fatalf("put: %v", err)
	}
	t.Cleanup(func() { _ = c.Delete(context.Background(), owner, token) })

	got, err := c.Get(ctx, owner, token, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("get returned %q, want %q", got, plaintext)
	}

	wrong := randomKey(t)
	if _, err := c.Get(ctx, owner, token, wrong); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get with wrong key = %v, want ErrForbidden", err)
	}

	if err := c.Delete(ctx, owner, token); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, owner, token, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
	// Delete is idempotent: removing the now-absent object is a no-op.
	if err := c.Delete(ctx, owner, token); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestSidecarTenantIsolation(t *testing.T) {
	c := newSidecarClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	ownerA := randomOwner(t)
	ownerB := randomOwner(t)
	token := randomHex(t, 16)
	key := randomKey(t)

	if err := c.Put(ctx, ownerA, token, []byte("owned by A"), key); err != nil {
		t.Fatalf("put A: %v", err)
	}
	t.Cleanup(func() { _ = c.Delete(context.Background(), ownerA, token) })

	// Same token and same key, different owner: the per-user tenant
	// prefix must keep B from reading A's object.
	if _, err := c.Get(ctx, ownerB, token, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrNotFound", err)
	}
}

func TestSidecarGetMissingIsNotFound(t *testing.T) {
	c := newSidecarClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if _, err := c.Get(ctx, randomOwner(t), randomHex(t, 16), randomKey(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing = %v, want ErrNotFound", err)
	}
}
