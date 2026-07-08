package buckets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/bucketstub"
)

const (
	testOwner      = "user_test"
	testOtherOwner = "user_other"
	testToken      = "************************************"
	testBucket     = "test-attachments-bucket"
)

// newStubbedClient wires a client to an in-memory sidecar stub that
// speaks the same path-style, multitenant S3 surface as the real
// colocated buckets sidecar.
func newStubbedClient(t *testing.T) (*bucketstub.Store, *Client) {
	t.Helper()
	store := bucketstub.NewStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+testBucket+"/{key}", store.Handle)
	mux.HandleFunc("/"+testBucket, store.Handle)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return store, NewClient(srv.URL, testBucket, srv.Client())
}

func TestClientPutGetRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, encryptionKeySize)
	plaintext := []byte("hello buckets")
	_, c := newStubbedClient(t)

	if err := c.Put(context.Background(), testOwner, testToken, plaintext, key); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := c.Get(context.Background(), testOwner, testToken, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestClientGetEmptyValue(t *testing.T) {
	key := bytes.Repeat([]byte{1}, encryptionKeySize)
	_, c := newStubbedClient(t)

	if err := c.Put(context.Background(), testOwner, testToken, nil, key); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := c.Get(context.Background(), testOwner, testToken, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty value decoded to %d bytes", len(got))
	}
}

func TestClientGetWrongKeyIsForbidden(t *testing.T) {
	key := bytes.Repeat([]byte{2}, encryptionKeySize)
	wrong := bytes.Repeat([]byte{3}, encryptionKeySize)
	_, c := newStubbedClient(t)

	if err := c.Put(context.Background(), testOwner, testToken, []byte("secret"), key); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := c.Get(context.Background(), testOwner, testToken, wrong); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestClientGetMissingIsNotFound(t *testing.T) {
	_, c := newStubbedClient(t)
	if _, err := c.Get(context.Background(), testOwner, testToken, make([]byte, encryptionKeySize)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestClientDeleteRemovesObject(t *testing.T) {
	key := bytes.Repeat([]byte{4}, encryptionKeySize)
	_, c := newStubbedClient(t)

	if err := c.Put(context.Background(), testOwner, testToken, []byte("bye"), key); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := c.Delete(context.Background(), testOwner, testToken); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(context.Background(), testOwner, testToken, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestClientDeleteIsIdempotent(t *testing.T) {
	_, c := newStubbedClient(t)
	if err := c.Delete(context.Background(), testOwner, testToken); err != nil {
		t.Fatalf("delete of absent object should be a no-op, got %v", err)
	}
}

// TestClientTenantIsolation proves the per-user prefix is a real
// boundary: an object written under one owner is invisible to a
// request that resolves to a different owner, even with the same
// access token and key.
func TestClientTenantIsolation(t *testing.T) {
	key := bytes.Repeat([]byte{5}, encryptionKeySize)
	_, c := newStubbedClient(t)

	if err := c.Put(context.Background(), testOwner, testToken, []byte("mine"), key); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := c.Get(context.Background(), testOtherOwner, testToken, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestClientRejectsInvalidOwner(t *testing.T) {
	_, c := newStubbedClient(t)
	if err := c.Put(context.Background(), "", testToken, []byte("x"), make([]byte, encryptionKeySize)); err == nil {
		t.Fatal("expected an error for an empty owner")
	}
}

// TestClientPutWireContract locks the on-the-wire shape the sidecar
// requires: a path-style PUT to /{bucket}/{key} where {bucket} is the
// configured bucket the sidecar routes to, the two multitenant
// headers, a 32-byte base64 key, and an explicit Content-Length.
func TestClientPutWireContract(t *testing.T) {
	key := bytes.Repeat([]byte{9}, encryptionKeySize)
	plaintext := []byte("xyz")
	var (
		gotMethod string
		gotPath   string
		gotTenant string
		gotKeyHdr string
		gotLen    int64
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotTenant = r.Header.Get(headerTenantID)
		gotKeyHdr = r.Header.Get(headerEncryptionKey)
		gotLen = r.ContentLength
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, testBucket, srv.Client())
	if err := c.Put(context.Background(), testOwner, testToken, plaintext, key); err != nil {
		t.Fatalf("put: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if want := "/" + testBucket + "/" + testToken; gotPath != want {
		t.Errorf("path = %s, want %s", gotPath, want)
	}
	if want := tenantPrefix + testOwner; gotTenant != want {
		t.Errorf("tenant = %s, want %s", gotTenant, want)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotKeyHdr)
	if err != nil || len(decoded) != encryptionKeySize {
		t.Errorf("encryption key header = %q (decode err %v, len %d)", gotKeyHdr, err, len(decoded))
	}
	if gotLen != int64(len(plaintext)) {
		t.Errorf("content-length = %d, want %d", gotLen, len(plaintext))
	}
	if !bytes.Equal(gotBody, plaintext) {
		t.Errorf("body = %q, want %q", gotBody, plaintext)
	}
}
