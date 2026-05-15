//go:build smoke

// Package smoke is the adversarial test suite for the sync enclave.
// Every test in this package tries to break a specific invariant the
// enclave claims to hold (confidentiality, AEAD integrity, AAD
// binding, CAS, etc.). Tests are guarded behind the `smoke` build tag
// so they do not run under `go test ./...` — they need a live HTTP
// stack and are slower than the unit tests.
//
//	go test -tags=smoke -v ./internal/localstack/smoke
//
// Each test file maps to one invariant; the bug-to-test mapping is in
// LOCAL_TESTING.md and §16.26 of syncplan.md.
package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/localstack"
)

// fixture is the per-test scaffold: a freshly-started stack, a default
// user JWT, a random CEK that has been registered as the user's
// current key.
type fixture struct {
	t     *testing.T
	stack *localstack.Stack

	userSub string
	jwt     string

	cek    []byte
	cekKID string
	cekB64 string
}

// newFixture starts a fresh stack, registers a key for `user_smoke`,
// and returns a handle. t.Cleanup tears the stack down so tests do
// not leak listeners.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	stack, err := localstack.Start(localstack.Config{})
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	t.Cleanup(stack.Stop)

	sub := "user_smoke"
	tok, err := stack.MintJWT(sub, time.Hour)
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}

	cek := make([]byte, crypto.KeySize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand cek: %v", err)
	}
	kidBytes, err := crypto.DeriveKeyID(cek)
	if err != nil {
		t.Fatalf("derive kid: %v", err)
	}
	cekKID := crypto.KeyIDHex(kidBytes)
	cekB64 := base64.StdEncoding.EncodeToString(cek)

	f := &fixture{
		t:       t,
		stack:   stack,
		userSub: sub,
		jwt:     tok,
		cek:     cek,
		cekKID:  cekKID,
		cekB64:  cekB64,
	}
	// Register the CEK so subsequent push/pull calls succeed end-to-end.
	if _, _, err := f.registerKey("init-idem", "start_fresh"); err != nil {
		t.Fatalf("register initial key: %v", err)
	}
	return f
}

// post does an authenticated POST to the enclave and returns the
// (status, body) tuple. Test code asserts on the status and decodes
// the body when relevant.
func (f *fixture) post(path string, payload any, jwtOverride ...string) (int, []byte) {
	f.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.stack.EnclaveURL+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatalf("new req: %v", err)
	}
	tok := f.jwt
	if len(jwtOverride) == 1 {
		tok = jwtOverride[0]
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// registerKey wraps POST /v1/key/register. createdVia is the
// `created_via` field — "start_fresh" skips the
// EXISTING_DATA_UNDER_OTHER_KEY check.
func (f *fixture) registerKey(idem, createdVia string) (int, []byte, error) {
	status, body := f.post("/v1/key/register", map[string]any{
		"key":             f.cekB64,
		"if_match":        "*",
		"created_via":     createdVia,
		"idempotency_key": idem,
	})
	if status >= 300 {
		return status, body, fmt.Errorf("register: status=%d body=%s", status, body)
	}
	return status, body, nil
}

// push wraps POST /v1/sync/push with the fixture's CEK + jwt.
// `plaintext` is the raw plaintext bytes; we base64 them on the wire.
// `ifMatch` is the literal CAS token: pass nil for create, &"3" for
// update with explicit etag, &"*" is not legal here.
func (f *fixture) push(scope, id string, plaintext []byte, ifMatch *string, idem string, conflictPolicy string) (int, pushResponse) {
	f.t.Helper()
	payload := map[string]any{
		"scope":           scope,
		"id":              id,
		"key":             f.cekB64,
		"plaintext":       base64.StdEncoding.EncodeToString(plaintext),
		"if_match":        ifMatch,
		"idempotency_key": idem,
	}
	if conflictPolicy != "" {
		payload["conflict_policy"] = conflictPolicy
	}
	status, body := f.post("/v1/sync/push", payload)
	var resp pushResponse
	_ = json.Unmarshal(body, &resp)
	resp.Raw = body
	return status, resp
}

// pull wraps POST /v1/sync/pull with a single id and a single key.
// `cekB64Override` lets callers use a key OTHER than the fixture's
// (e.g. random bytes for wrong-CEK tests).
func (f *fixture) pullOne(scope, id, cekB64Override string) (int, pullItem) {
	f.t.Helper()
	keyB64 := f.cekB64
	if cekB64Override != "" {
		keyB64 = cekB64Override
	}
	status, body := f.post("/v1/sync/pull", map[string]any{
		"scope": scope,
		"ids":   []string{id},
		"keys":  []map[string]any{{"key": keyB64}},
	})
	var resp pullResponse
	_ = json.Unmarshal(body, &resp)
	if len(resp.Items) == 0 {
		return status, pullItem{}
	}
	return status, resp.Items[0]
}

// deleteRow wraps POST /v1/sync/delete.
func (f *fixture) deleteRow(scope, id string, ifMatch *string, idem string) (int, []byte) {
	f.t.Helper()
	return f.post("/v1/sync/delete", map[string]any{
		"scope":           scope,
		"id":              id,
		"if_match":        ifMatch,
		"idempotency_key": idem,
		"key":             f.cekB64,
	})
}

// migrate wraps POST /v1/blobs/migrate. Used by T13 to drive legacy
// v0 → v2 migration end-to-end.
func (f *fixture) migrate(scope string, ids []string, targetCEKB64 string) (int, []byte) {
	f.t.Helper()
	return f.post("/v1/blobs/migrate", map[string]any{
		"scope":  scope,
		"ids":    ids,
		"keys":   []map[string]any{{"key": f.cekB64}},
		"target": map[string]any{"key": targetCEKB64},
	})
}

// --- wire response shapes (subset; tests decode what they need) -----------

type pushResponse struct {
	OK    bool   `json:"ok"`
	ETag  string `json:"etag"`
	KeyID string `json:"key_id"`
	Code  string `json:"code,omitempty"`
	Raw   []byte `json:"-"`
}

type pullItem struct {
	ID          string `json:"id"`
	OK          bool   `json:"ok"`
	Plaintext   string `json:"plaintext,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	ETag        string `json:"etag,omitempty"`
	NeedsRewrap bool   `json:"needs_rewrap,omitempty"`
	Code        string `json:"code,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type pullResponse struct {
	Items []pullItem `json:"items"`
}
