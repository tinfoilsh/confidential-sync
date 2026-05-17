package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// bucketsStub mirrors the subset of buckets.tinfoil.sh that the
// enclave's buckets.Client talks to: a single tenant keyed by API
// key, with PUT/GET/DELETE on /items/{token}. Values are stored
// in-memory along with the encryption keys the caller declared at
// PUT-time, and GET verifies the supplied X-Encryption-Key matches
// one of the slots — same model real buckets uses.
type bucketsStub struct {
	t      *testing.T
	mu     sync.Mutex
	apiKey string
	items  map[string]bucketsItem
	server *httptest.Server
}

type bucketsItem struct {
	Value          []byte
	EncryptionKeys [][]byte
}

func newBucketsStub(t *testing.T) *bucketsStub {
	t.Helper()
	s := &bucketsStub{
		t:      t,
		apiKey: "test-api-key",
		items:  map[string]bucketsItem{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *bucketsStub) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/items/") {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/items/")
	if got := r.Header.Get("Authorization"); got != "Bearer "+s.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var body struct {
			Value          string   `json:"value"`
			EncryptionKeys []string `json:"encryption_keys"`
			Format         int      `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		value, err := base64.StdEncoding.DecodeString(body.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		keys := make([][]byte, 0, len(body.EncryptionKeys))
		for _, k := range body.EncryptionKeys {
			kb, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			keys = append(keys, kb)
		}
		s.mu.Lock()
		s.items[token] = bucketsItem{Value: value, EncryptionKeys: keys}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		s.mu.Lock()
		item, ok := s.items[token]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		supplied, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Encryption-Key"))
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		match := false
		for _, k := range item.EncryptionKeys {
			if len(k) == len(supplied) && string(k) == string(supplied) {
				match = true
				break
			}
		}
		if !match {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Value string `json:"value"`
		}{Value: base64.StdEncoding.EncodeToString(item.Value)})

	case http.MethodDelete:
		s.mu.Lock()
		_, existed := s.items[token]
		delete(s.items, token)
		s.mu.Unlock()
		if !existed {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *bucketsStub) has(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[token]
	return ok
}

func (s *bucketsStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
