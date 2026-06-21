package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recordedReq struct {
	method string
	path   string
	auth   string
	body   []byte
	header http.Header
	query  string
}

type stub struct {
	t        *testing.T
	server   *httptest.Server
	requests []recordedReq
	handlers map[string]http.HandlerFunc
}

func newStub(t *testing.T) *stub {
	t.Helper()
	s := &stub{t: t, handlers: map[string]http.HandlerFunc{}}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stub) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.requests = append(s.requests, recordedReq{
		method: r.Method,
		path:   r.URL.Path,
		auth:   r.Header.Get("Authorization"),
		body:   body,
		header: r.Header.Clone(),
		query:  r.URL.RawQuery,
	})
	key := r.Method + " " + r.URL.Path
	if h, ok := s.handlers[key]; ok {
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		h(w, r)
		return
	}
	for prefix, h := range s.handlers {
		if strings.HasSuffix(prefix, "*") {
			pPrefix := strings.TrimSuffix(prefix, "*")
			if strings.HasPrefix(key, pPrefix) {
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				h(w, r)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func (s *stub) handle1(method, path string, h http.HandlerFunc) {
	s.handlers[method+" "+path] = h
}

func TestPutBlobSuccess(t *testing.T) {
	st := newStub(t)
	st.handle1("PUT", "/api/sync/blob/chat/chat_1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-jwt" {
			t.Errorf("auth header: %q", got)
		}
		if got := r.Header.Get("X-Key-Id"); got != strings.Repeat("a", 32) {
			t.Errorf("x-key-id: %q", got)
		}
		if got := r.Header.Get("If-Match"); got != "5" {
			t.Errorf("if-match: %q", got)
		}
		if got := r.Header.Get("X-Idempotency-Key"); got != "idem-1" {
			t.Errorf("idem: %q", got)
		}
		if got := r.Header.Get("X-Operation-Hash"); got != "opHash" {
			t.Errorf("op hash: %q", got)
		}
		w.Header().Set("ETag", "6")
		w.Header().Set("X-Key-Id", strings.Repeat("a", 32))
		json.NewEncoder(w).Encode(map[string]string{"etag": "6"})
	})

	c := NewClient(st.server.URL, nil)
	resp, err := c.PutBlob(context.Background(), PutBlobRequest{
		Scope:          "chat",
		ID:             "chat_1",
		JWT:            "test-jwt",
		KeyIDHex:       strings.Repeat("a", 32),
		IfMatch:        "5",
		IdempotencyKey: "idem-1",
		OperationHash:  "opHash",
		Ciphertext:     []byte("envelope"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ETag != "6" {
		t.Fatalf("etag: %q", resp.ETag)
	}
}

func TestPutBlobStaleBlob(t *testing.T) {
	st := newStub(t)
	st.handle1("PUT", "/api/sync/blob/chat/chat_1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		json.NewEncoder(w).Encode(map[string]string{
			"code":         StatusStaleBlob,
			"current_etag": "9",
		})
	})
	c := NewClient(st.server.URL, nil)
	_, err := c.PutBlob(context.Background(), PutBlobRequest{Scope: "chat", ID: "chat_1", JWT: "j"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsCode(err, StatusStaleBlob) {
		t.Fatalf("expected STALE_BLOB, got %v", err)
	}
}

func TestRegisterKeyExistingDataConflict(t *testing.T) {
	st := newStub(t)
	st.handle1("POST", "/api/sync/keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"code":           StatusExistingDataUnderOtherKey,
			"current_key_id": strings.Repeat("b", 32),
		})
	})
	c := NewClient(st.server.URL, nil)
	_, err := c.RegisterKey(context.Background(), RegisterKeyRequest{
		JWT:        "j",
		KeyIDHex:   strings.Repeat("a", 32),
		CreatedVia: "passkey",
		IfMatch:    "*",
	})
	if !IsCode(err, StatusExistingDataUnderOtherKey) {
		t.Fatalf("expected conflict, got %v", err)
	}
	var e *Error
	if !cpErrAs(err, &e) {
		t.Fatalf("not *Error")
	}
	if e.CurrentKeyID != strings.Repeat("b", 32) {
		t.Fatalf("unexpected current_key_id: %q", e.CurrentKeyID)
	}
}

func TestGetBlobReturnsCiphertextAndHeaders(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/blob/chat/chat_1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "7")
		w.Header().Set("X-Key-Id", strings.Repeat("c", 32))
		w.Write([]byte("opaque-bytes"))
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.GetBlob(context.Background(), "chat", "chat_1", "j", "user_x")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Ciphertext) != "opaque-bytes" {
		t.Fatalf("body: %q", resp.Ciphertext)
	}
	if resp.ETag != "7" || resp.KeyID != strings.Repeat("c", 32) {
		t.Fatalf("headers: etag=%q keyid=%q", resp.ETag, resp.KeyID)
	}
}

func TestListStatusEncodesQuery(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/list-status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "chat" {
			t.Errorf("scope: %q", r.URL.Query().Get("scope"))
		}
		if r.URL.Query().Get("cursor") != "c1" {
			t.Errorf("cursor: %q", r.URL.Query().Get("cursor"))
		}
		if r.URL.Query().Get("limit") != "50" {
			t.Errorf("limit: %q", r.URL.Query().Get("limit"))
		}
		if r.URL.Query().Get("project_id") != "proj_1" {
			t.Errorf("project_id: %q", r.URL.Query().Get("project_id"))
		}
		if r.URL.Query().Get("direction") != "" {
			t.Errorf("direction should be omitted when empty: %q", r.URL.Query().Get("direction"))
		}
		json.NewEncoder(w).Encode(ListStatusResponse{
			Updates:    []BlobMeta{{ID: "a", ETag: "1", KeyID: strings.Repeat("a", 32)}},
			NextCursor: "c2",
		})
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.ListStatus(context.Background(), "chat", "c1", 50, "j", "user_x", "proj_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Updates) != 1 || resp.NextCursor != "c2" {
		t.Fatalf("response: %+v", resp)
	}
}

func TestListStatusEncodesDirection(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/list-status", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("direction"); got != "desc" {
			t.Errorf("direction: got %q want desc", got)
		}
		json.NewEncoder(w).Encode(ListStatusResponse{})
	})
	c := NewClient(st.server.URL, nil)
	if _, err := c.ListStatus(context.Background(), "project", "", 50, "j", "user_x", "", "desc"); err != nil {
		t.Fatal(err)
	}
}

func TestProjectDocumentRouting(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/blob/project_document/proj_1/doc_2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "1")
		w.Header().Set("X-Key-Id", strings.Repeat("d", 32))
		w.Write([]byte("doc-blob"))
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.GetBlob(context.Background(), "project_document", "proj_1/doc_2", "j", "user_x")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Ciphertext) != "doc-blob" {
		t.Fatalf("body: %q", resp.Ciphertext)
	}
}

func TestDeleteBlobSendsHeaders(t *testing.T) {
	st := newStub(t)
	called := false
	st.handle1("DELETE", "/api/sync/blob/project/proj_1", func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("If-Match") != "3" {
			t.Errorf("if-match: %q", r.Header.Get("If-Match"))
		}
		if r.Header.Get("X-Idempotency-Key") != "del-1" {
			t.Errorf("idem: %q", r.Header.Get("X-Idempotency-Key"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil)
	if _, err := c.DeleteBlob(context.Background(), DeleteBlobRequest{
		Scope:          "project",
		ID:             "proj_1",
		JWT:            "j",
		IfMatch:        "3",
		IdempotencyKey: "del-1",
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatalf("handler not invoked")
	}
}

func TestIsCodeFalseOnPlainError(t *testing.T) {
	if IsCode(io.EOF, "ANYTHING") {
		t.Fatalf("plain error should not match")
	}
}

func TestParseErrorNoBody(t *testing.T) {
	e := parseError(500, nil)
	if e == nil {
		t.Fatal("nil error")
	}
	if !strings.Contains(e.Error(), "500") {
		t.Fatalf("error string: %q", e.Error())
	}
}

func TestGetCurrentKeyNotFound(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/keys/current", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.GetCurrentKey(context.Background(), "j", "user_x")
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on 404")
	}
}

// The controlplane's no-key 200 shape carries an empty created_at
// string. Decoding it must not fail (it once decoded into time.Time,
// which rejects "" and turned every no-key user's key/current into a
// 500, blocking legacy migration).
func TestGetCurrentKeyDecodesEmptyCreatedAt(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/keys/current", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"","etag":"","bundles":{},"created_via":"","created_at":"","has_data":true}`))
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.GetCurrentKey(context.Background(), "j", "user_x")
	if err != nil {
		t.Fatalf("decode no-key response: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.KeyID != "" {
		t.Fatalf("expected empty key_id, got %q", resp.KeyID)
	}
	if !resp.HasData {
		t.Fatal("expected has_data=true")
	}
	if resp.CreatedAt != "" {
		t.Fatalf("expected empty created_at, got %q", resp.CreatedAt)
	}
}

// A keyed response forwards created_at and each bundle's registered_at
// as the controlplane's already-formatted strings.
func TestGetCurrentKeyDecodesKeyedResponse(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/sync/keys/current", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"abc","etag":"3","created_via":"recovery","created_at":"2026-06-05T02:17:16.755Z","has_data":true,"bundles":{"cred-1":{"credential_id":"cred-1","kek_iv":"iv","encrypted_keys":"ct","registered_at":"2026-06-05T02:17:16.755Z"}}}`))
	})
	c := NewClient(st.server.URL, nil)
	resp, err := c.GetCurrentKey(context.Background(), "j", "user_x")
	if err != nil {
		t.Fatalf("decode keyed response: %v", err)
	}
	if resp.KeyID != "abc" || resp.CreatedAt != "2026-06-05T02:17:16.755Z" {
		t.Fatalf("unexpected key fields: %+v", resp)
	}
	b, ok := resp.Bundles["cred-1"]
	if !ok {
		t.Fatal("expected bundle cred-1")
	}
	if b.RegisteredAt != "2026-06-05T02:17:16.755Z" {
		t.Fatalf("unexpected registered_at: %q", b.RegisteredAt)
	}
}

func TestAddBundleForwardsCredentials(t *testing.T) {
	st := newStub(t)
	st.handle1("POST", "/api/sync/keys/"+strings.Repeat("a", 32)+"/bundles", func(w http.ResponseWriter, r *http.Request) {
		var got map[string]string
		json.NewDecoder(r.Body).Decode(&got)
		if got["credential_id"] != "cred-1" || got["kek_iv"] != "iv" || got["encrypted_keys"] != "ct" {
			t.Errorf("payload: %+v", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil)
	if err := c.AddBundle(context.Background(), AddBundleRequest{
		JWT: "j", KeyIDHex: strings.Repeat("a", 32),
		CredentialID: "cred-1", KEKIV: "iv", EncryptedKeys: "ct",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGetLegacyAttachmentRejectsOversizedBody(t *testing.T) {
	// Shrink the cap for the duration of the test so we can prove the
	// oversize-body rejection without streaming 64 MiB through the
	// fixture. The cap is a package-level var precisely so tests can
	// pick a small value here.
	orig := maxLegacyAttachmentBytes
	maxLegacyAttachmentBytes = 1024
	defer func() { maxLegacyAttachmentBytes = orig }()

	st := newStub(t)
	st.handle1("GET", "/api/storage/attachment/att_1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(repeatingReader('x'), int64(maxLegacyAttachmentBytes+1)))
	})
	c := NewClient(st.server.URL, nil)
	_, err := c.GetLegacyAttachment(context.Background(), "j", "user_x", "att_1")
	if err == nil || !strings.Contains(err.Error(), "legacy attachment exceeds") {
		t.Fatalf("expected oversized attachment error, got %v", err)
	}
}

func TestGetLegacyAttachmentMapsNotFound(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/storage/attachment/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := NewClient(st.server.URL, nil)
	_, err := c.GetLegacyAttachment(context.Background(), "j", "user_x", "missing")
	if !errors.Is(err, ErrLegacyAttachmentNotFound) {
		t.Fatalf("expected ErrLegacyAttachmentNotFound, got %v", err)
	}
}

// A 410 means the attachment is already promoted to v2; the rewrap
// path treats it as a no-op skip rather than a failure, so it must
// surface as the dedicated sentinel and not a generic error.
func TestGetLegacyAttachmentMapsGone(t *testing.T) {
	st := newStub(t)
	st.handle1("GET", "/api/storage/attachment/already_v2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	})
	c := NewClient(st.server.URL, nil)
	_, err := c.GetLegacyAttachment(context.Background(), "j", "user_x", "already_v2")
	if !errors.Is(err, ErrLegacyAttachmentGone) {
		t.Fatalf("expected ErrLegacyAttachmentGone, got %v", err)
	}
}

func TestDeleteAttachmentIndex(t *testing.T) {
	st := newStub(t)
	st.handle1("DELETE", "/api/sync/attachment-index/att_1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-jwt" {
			t.Errorf("auth header: %q", got)
		}
		if got := r.Header.Get(HeaderServiceSecret); got != "sync-secret" {
			t.Errorf("service secret header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil, WithServiceSecret("sync-secret"))
	if err := c.DeleteAttachmentIndex(context.Background(), "test-jwt", "user_x", "att_1"); err != nil {
		t.Fatalf("delete attachment index: %v", err)
	}
}

type repeatingReader byte

func (r repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// cpErrAs is a tiny helper to keep tests readable without leaking errors.As
// into every assertion.
func cpErrAs(err error, target **Error) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	*target = e
	return true
}

func TestAddAuthStampsClerkUserIDFromCaller(t *testing.T) {
	st := newStub(t)
	st.handle1("DELETE", "/api/sync/attachment-index/att_1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderClerkUserID); got != "user_abc123" {
			t.Errorf("clerk-user-id header: %q, want %q", got, "user_abc123")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer arbitrary-jwt" {
			t.Errorf("authorization header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil, WithServiceSecret("sync-secret"))
	if err := c.DeleteAttachmentIndex(context.Background(), "arbitrary-jwt", "user_abc123", "att_1"); err != nil {
		t.Fatalf("delete attachment index: %v", err)
	}
}

func TestNotifyImportCompleteOmitsEmptyBearer(t *testing.T) {
	st := newStub(t)
	st.handle1("POST", "/api/sync/notify-import-complete", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderAuth); got != "" {
			t.Errorf("authorization header: %q, want empty", got)
		}
		if got := r.Header.Get(HeaderClerkUserID); got != "user_real" {
			t.Errorf("clerk-user-id header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil, WithServiceSecret("sync-secret"))
	if err := c.NotifyImportComplete(context.Background(), "user_real", "job_1", "chatgpt", 3, 0); err != nil {
		t.Fatalf("notify import complete: %v", err)
	}
}

func TestAddAuthOmitsClerkUserIDWhenCallerOmitsIt(t *testing.T) {
	st := newStub(t)
	st.handle1("DELETE", "/api/sync/attachment-index/att_1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderClerkUserID); got != "" {
			t.Errorf("clerk-user-id header without explicit subject: %q, want empty", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil, WithServiceSecret("sync-secret"))
	if err := c.DeleteAttachmentIndex(context.Background(), "arbitrary-jwt", "", "att_1"); err != nil {
		t.Fatalf("delete attachment index: %v", err)
	}
}

func TestAddAuthIgnoresJWTPayloadForUserID(t *testing.T) {
	st := newStub(t)
	st.handle1("DELETE", "/api/sync/attachment-index/att_1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderClerkUserID); got != "user_real" {
			t.Errorf("clerk-user-id header must come from the caller-supplied verified subject, got %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(st.server.URL, nil, WithServiceSecret("sync-secret"))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user_spoofed"}`))
	maliciousJWT := header + "." + body + ".sig"
	if err := c.DeleteAttachmentIndex(context.Background(), maliciousJWT, "user_real", "att_1"); err != nil {
		t.Fatalf("delete attachment index: %v", err)
	}
}
