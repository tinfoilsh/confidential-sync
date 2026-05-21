package buckets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const testAccessToken = "123e4567-e89b-12d3-a456-426614174000"

func TestClientPutUsesMultipartFormat(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plaintext := []byte("hello")
	var gotFields []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Path != "/put" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer api-key" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "multipart/form-data;") {
			t.Fatalf("content-type = %q", got)
		}
		reader, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			name := part.FormName()
			gotFields = append(gotFields, name)
			body, err := io.ReadAll(part)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "access_token":
				if string(body) != testAccessToken {
					t.Fatalf("access token = %q", body)
				}
			case "encryption_keys":
				if string(body) != base64.StdEncoding.EncodeToString(key) {
					t.Fatalf("key = %q", body)
				}
			case "plaintext_length":
				if string(body) != "5" {
					t.Fatalf("plaintext_length = %q", body)
				}
			case "data":
				if !bytes.Equal(body, plaintext) {
					t.Fatalf("data = %q", body)
				}
			default:
				t.Fatalf("unexpected field %q", name)
			}
		}
		if !slices.Equal(gotFields, []string{"access_token", "encryption_keys", "plaintext_length", "data"}) {
			t.Fatalf("field order = %v", gotFields)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"plaintext_length": len(plaintext),
			"version":          1,
			"created_at":       "2026-04-10T12:00:00Z",
		})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	if err := c.Put(context.Background(), testAccessToken, plaintext, key); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func TestClientGetUsesJSONAndReturnsRawBytes(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	want := []byte{0, 1, 2, 255}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Path != "/get" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer api-key" {
			t.Fatalf("authorization = %q", got)
		}
		var body getRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AccessToken != testAccessToken {
			t.Fatalf("access token = %q", body.AccessToken)
		}
		if body.EncryptionKey != base64.StdEncoding.EncodeToString(key) {
			t.Fatalf("key = %q", body.EncryptionKey)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(want)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	got, err := c.Get(context.Background(), testAccessToken, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClientDeleteUsesJSONAndNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Path != "/delete" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var body accessTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AccessToken != testAccessToken {
			t.Fatalf("access token = %q", body.AccessToken)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	if err := c.Delete(context.Background(), testAccessToken); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestClientPreservesForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "wrong key"})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	_, err := c.Get(context.Background(), testAccessToken, make([]byte, 32))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestClientPreservesNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	_, err := c.Get(context.Background(), testAccessToken, make([]byte, 32))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestClientAllowsEmptyRawValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	got, err := c.Get(context.Background(), testAccessToken, make([]byte, 32))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty value decoded to %d bytes", len(got))
	}
}
