package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
)

// TestAttachmentGetResolvesOwnerFromControlplane proves the read path
// derives the buckets tenant from the controlplane index rather than
// the caller: the request carries only {id, att_key}, yet the enclave
// finds the object stored under the owner's per-user tenant.
func TestAttachmentGetResolvesOwnerFromControlplane(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	attID := "0123456789abcdef0123456789abcdef0123"
	attKey := bytes.Repeat([]byte{8}, 32)
	plaintext := []byte("attachment-plaintext")

	tenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	f.bk.items.Put(attID, bucketsItem{
		Tenant:         tenant,
		Value:          plaintext,
		EncryptionKeys: [][]byte{attKey},
	})
	f.cp.mu.Lock()
	f.cp.attachmentOwner = map[string]string{attID: f.userSub}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/attachment/get", AttachmentGetRequest{
		ID:     attID,
		AttKey: base64.StdEncoding.EncodeToString(attKey),
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: %d %s", resp.StatusCode, body)
	}
	var got AttachmentGetResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	gotPT, err := base64.StdEncoding.DecodeString(got.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if !bytes.Equal(gotPT, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", gotPT, plaintext)
	}
}

// TestAttachmentGetUnknownOwnerIsNotFound proves that when the
// controlplane has no index row, the enclave returns 404 without ever
// addressing buckets — a logically deleted attachment is unreadable
// even if its blob still lingers awaiting the orphan reaper.
func TestAttachmentGetUnknownOwnerIsNotFound(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	attID := "ffffffffffffffffffffffffffffffffffff"
	attKey := bytes.Repeat([]byte{1}, 32)

	resp, body := f.post("/v1/attachment/get", AttachmentGetRequest{
		ID:     attID,
		AttKey: base64.StdEncoding.EncodeToString(attKey),
	}, tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d %s", resp.StatusCode, body)
	}
}
