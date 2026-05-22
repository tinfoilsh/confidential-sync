package bucketstub

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	minAccessTokenLength = 36
	maxAccessTokenLength = 76
	defaultPartSize      = 64 << 20
)

type Store struct {
	mu     sync.Mutex
	apiKey string
	items  map[string]Item
}

type Item struct {
	Value          []byte
	EncryptionKeys [][]byte
	Version        int64
	CreatedAt      time.Time
	PartSize       int64
}

func NewStore(apiKey string) *Store {
	return &Store{
		apiKey: apiKey,
		items:  map[string]Item{},
	}
}

func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+s.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.URL.Path {
	case "/put":
		s.put(w, r)
	case "/get":
		s.get(w, r)
	case "/delete":
		s.delete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Store) Put(token string, item Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item.Version == 0 {
		item.Version = 1
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	if item.PartSize == 0 {
		item.PartSize = defaultPartSize
	}
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

func (s *Store) put(w http.ResponseWriter, r *http.Request) {
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var (
		token           string
		keys            [][]byte
		value           []byte
		plaintextLength int64 = -1
		partSize              = int64(defaultPartSize)
		sawData         bool
	)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if sawData {
			http.Error(w, "data must be last", http.StatusBadRequest)
			return
		}
		name := part.FormName()
		switch name {
		case "access_token":
			token, err = readPartString(part)
		case "encryption_keys":
			var encoded string
			encoded, err = readPartString(part)
			if err == nil {
				var key []byte
				key, err = base64.StdEncoding.DecodeString(encoded)
				if err == nil && len(key) != 32 {
					err = errBadKey
				}
				if err == nil {
					keys = append(keys, key)
				}
			}
		case "part_size":
			var encoded string
			encoded, err = readPartString(part)
			if err == nil {
				partSize, err = strconv.ParseInt(encoded, 10, 64)
				if err == nil && partSize <= 0 {
					err = errBadPartSize
				}
			}
		case "plaintext_length":
			var encoded string
			encoded, err = readPartString(part)
			if err == nil {
				plaintextLength, err = strconv.ParseInt(encoded, 10, 64)
			}
		case "data":
			if plaintextLength < 0 {
				http.Error(w, "plaintext_length is required before data", http.StatusBadRequest)
				return
			}
			value, err = io.ReadAll(part)
			sawData = true
		default:
			http.Error(w, "unknown field", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if !validAccessToken(token) {
		http.Error(w, "bad access token", http.StatusBadRequest)
		return
	}
	if len(keys) == 0 {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	if plaintextLength < 0 || !sawData {
		http.Error(w, "missing data", http.StatusBadRequest)
		return
	}
	if int64(len(value)) != plaintextLength {
		http.Error(w, "plaintext_length mismatch", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	version := int64(1)
	createdAt := time.Now().UTC()
	if existing, ok := s.items[token]; ok {
		version = existing.Version + 1
		if !existing.CreatedAt.IsZero() {
			createdAt = existing.CreatedAt
		}
	}
	s.items[token] = cloneItem(Item{
		Value:          value,
		EncryptionKeys: keys,
		Version:        version,
		CreatedAt:      createdAt,
		PartSize:       partSize,
	})
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		PlaintextLength int64  `json:"plaintext_length"`
		Version         int64  `json:"version"`
		CreatedAt       string `json:"created_at"`
	}{
		PlaintextLength: plaintextLength,
		Version:         version,
		CreatedAt:       createdAt.Format(time.RFC3339Nano),
	})
}

func (s *Store) get(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessToken   string `json:"access_token"`
		EncryptionKey string `json:"encryption_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !validAccessToken(body.AccessToken) {
		http.Error(w, "bad access token", http.StatusBadRequest)
		return
	}
	item, ok := s.Item(body.AccessToken)
	if !ok {
		http.NotFound(w, r)
		return
	}
	supplied, err := base64.StdEncoding.DecodeString(body.EncryptionKey)
	if err != nil {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	if len(supplied) != 32 {
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
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Version", strconv.FormatInt(item.Version, 10))
	w.Header().Set("X-Created-At", item.CreatedAt.Format(time.RFC3339Nano))
	w.Header().Set("X-Num-Encryption-Keys", strconv.Itoa(len(item.EncryptionKeys)))
	w.Header().Set("X-Encryption-Key-Fingerprints", encryptionKeyFingerprints(item.EncryptionKeys))
	w.Header().Set("X-Plaintext-Length", strconv.Itoa(len(item.Value)))
	w.Header().Set("X-Part-Size", strconv.FormatInt(item.PartSize, 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(item.Value)))
	_, _ = w.Write(item.Value)
}

func (s *Store) delete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !validAccessToken(body.AccessToken) {
		http.Error(w, "bad access token", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	delete(s.items, body.AccessToken)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func cloneItem(item Item) Item {
	cp := Item{
		Value:          append([]byte(nil), item.Value...),
		EncryptionKeys: make([][]byte, len(item.EncryptionKeys)),
		Version:        item.Version,
		CreatedAt:      item.CreatedAt,
		PartSize:       item.PartSize,
	}
	for i, k := range item.EncryptionKeys {
		cp.EncryptionKeys[i] = append([]byte(nil), k...)
	}
	return cp
}

var (
	errBadKey      = &badRequestError{message: "bad key"}
	errBadPartSize = &badRequestError{message: "part_size must be positive"}
)

type badRequestError struct {
	message string
}

func (e *badRequestError) Error() string {
	return e.message
}

func readPartString(part *multipart.Part) (string, error) {
	b, err := io.ReadAll(part)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func validAccessToken(token string) bool {
	if len(token) < minAccessTokenLength || len(token) > maxAccessTokenLength {
		return false
	}
	for _, ch := range token {
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func encryptionKeyFingerprints(keys [][]byte) string {
	fingerprints := make([]string, 0, len(keys))
	for _, key := range keys {
		sum := sha256.Sum256(key)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	return strings.Join(fingerprints, ",")
}
