package buckets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientEscapesAccessTokenPathSegment(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	if err := c.Delete(context.Background(), "a/b c?d"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gotPath != "/items/a%2Fb%20c%3Fd" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestClientPreservesForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "wrong key"})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "api-key", srv.Client())
	_, err := c.Get(context.Background(), "att", make([]byte, 32))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}
