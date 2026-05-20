package bucketstub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
)

const ExpectedFormat = 1

type Store struct {
	mu     sync.Mutex
	apiKey string
	items  map[string]Item
}

type Item struct {
	Value          []byte
	EncryptionKeys [][]byte
}

func NewStore(apiKey string) *Store {
	return &Store{
		apiKey: apiKey,
		items:  map[string]Item{},
	}
}

func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if got := r.Header.Get("Authorization"); got != "Bearer "+s.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.put(w, r, token)
	case http.MethodGet:
		s.get(w, r, token)
	case http.MethodDelete:
		s.delete(w, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Store) Put(token string, item Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[token] = cloneItem(item)
}

func (s *Store) Has(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[token]
	return ok
}

func (s *Store) Item(token string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[token]
	if !ok {
		return Item{}, false
	}
	return cloneItem(item), true
}

func (s *Store) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens := make([]string, 0, len(s.items))
	for token := range s.items {
		tokens = append(tokens, token)
	}
	return tokens
}

func (s *Store) put(w http.ResponseWriter, r *http.Request, token string) {
	var body struct {
		Value          string   `json:"value"`
		EncryptionKeys []string `json:"encryption_keys"`
		Format         int      `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Format != ExpectedFormat {
		http.Error(w, "unsupported format", http.StatusBadRequest)
		return
	}
	value, err := base64.StdEncoding.DecodeString(body.Value)
	if err != nil {
		http.Error(w, "bad value", http.StatusBadRequest)
		return
	}
	keys := make([][]byte, 0, len(body.EncryptionKeys))
	for _, k := range body.EncryptionKeys {
		kb, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		keys = append(keys, kb)
	}
	s.Put(token, Item{Value: value, EncryptionKeys: keys})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Store) get(w http.ResponseWriter, r *http.Request, token string) {
	item, ok := s.Item(token)
	if !ok {
		http.NotFound(w, r)
		return
	}
	supplied, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Encryption-Key"))
	if err != nil {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	match := false
	for _, k := range item.EncryptionKeys {
		if bytes.Equal(k, supplied) {
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
}

func (s *Store) delete(w http.ResponseWriter, token string) {
	s.mu.Lock()
	_, existed := s.items[token]
	delete(s.items, token)
	s.mu.Unlock()
	if !existed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func cloneItem(item Item) Item {
	cp := Item{
		Value:          append([]byte(nil), item.Value...),
		EncryptionKeys: make([][]byte, len(item.EncryptionKeys)),
	}
	for i, k := range item.EncryptionKeys {
		cp.EncryptionKeys[i] = append([]byte(nil), k...)
	}
	return cp
}
