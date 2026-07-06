package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-key", "test-model", nil)
}

func TestEmbedReturnsVectorsInInputOrder(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("unexpected auth header %q", got)
		}
		var req embeddingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model != "test-model" || len(req.Input) != 2 {
			t.Fatalf("unexpected request: %+v", req)
		}
		// Reply out of order to prove index-based reassembly.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"index": 1, "embedding": []float32{3, 4}},
				{"index": 0, "embedding": []float32{1, 2}},
			},
		})
	})
	got, err := c.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]float32{{1, 2}, {3, 4}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Embed = %v, want %v", got, want)
	}
}

func TestEmbedRejectsBadResponses(t *testing.T) {
	cases := map[string]string{
		"count mismatch":  `{"data":[{"index":0,"embedding":[1]}]}`,
		"index range":     `{"data":[{"index":0,"embedding":[1]},{"index":5,"embedding":[1]}]}`,
		"duplicate index": `{"data":[{"index":0,"embedding":[1]},{"index":0,"embedding":[1]}]}`,
		"empty vector":    `{"data":[{"index":0,"embedding":[1]},{"index":1,"embedding":[]}]}`,
	}
	for name, body := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		if _, err := c.Embed(context.Background(), []string{"a", "b"}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestEmbedSurfacesUpstreamStatus(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	})
	if _, err := c.Embed(context.Background(), []string{"a"}); err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestConfigured(t *testing.T) {
	if NewClient("", "k", "m", nil).Configured() {
		t.Fatal("empty base URL should not be configured")
	}
	if NewClient("http://x", "", "m", nil).Configured() {
		t.Fatal("empty api key should not be configured")
	}
	if !NewClient("http://x", "k", "m", nil).Configured() {
		t.Fatal("expected configured client")
	}
}
