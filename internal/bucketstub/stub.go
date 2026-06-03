// Package bucketstub is an in-memory stand-in for the colocated
// tinfoil-buckets-sidecar's S3-compatible API. It implements just the
// surface the enclave's buckets.Client exercises: path-style
// PutObject/GetObject/DeleteObject, all gated on the multitenant
// X-Tinfoil-Tenant-Id and X-Tinfoil-Encryption-Key headers. Objects
// are namespaced by tenant, and GET verifies the supplied key matches
// the one declared at PUT — the same model the real sidecar uses (a
// wrong key surfaces as a 400 DecryptionFailed instead of decrypting).
package bucketstub

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	defaultPartSize = 64 << 20
	// maxStubPlaintextBytes caps the object body the stub will buffer.
	// The real sidecar streams to object storage; the stub holds
	// everything in memory, so an unbounded read would let a
	// misconfigured or hostile client OOM the test harness.
	maxStubPlaintextBytes = 256 << 20

	headerTenantID      = "X-Tinfoil-Tenant-Id"
	headerEncryptionKey = "X-Tinfoil-Encryption-Key"
	encryptionKeySize   = 32
)

var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Store struct {
	mu    sync.Mutex
	items map[string]Item
}

// Item is a stored object. Tenant namespaces it; Value is the
// plaintext; EncryptionKeys holds the key it was sealed under so GET
// can reject a mismatched key.
type Item struct {
	Tenant         string
	Value          []byte
	EncryptionKeys [][]byte
	Version        int64
	CreatedAt      time.Time
	PartSize       int64
}

func NewStore() *Store {
	return &Store{items: map[string]Item{}}
}

// Put pre-seeds an object by token. Tests use it to stage attachments
// without going through an HTTP PUT; set Item.Tenant to the owning
// user's tenant so tenant-scoped GET/DELETE address it.
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

// Has reports whether any tenant holds the token. Attachment ids are
// globally unique, so tests assert presence by token alone.
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

// Handle dispatches the S3-style request. Harnesses register it for
// both "/{bucket}/{key}" (object ops) and "/{bucket}" (bucket ops).
func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	tenant, key, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	objectKey := r.PathValue("key")
	switch {
	case objectKey != "" && r.Method == http.MethodPut:
		s.putObject(w, r, tenant, key, objectKey)
	case objectKey != "" && r.Method == http.MethodGet:
		s.getObject(w, tenant, key, objectKey)
	case objectKey != "" && r.Method == http.MethodDelete:
		s.deleteObject(w, tenant, objectKey)
	default:
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest", "unsupported operation")
	}
}

func (s *Store) putObject(w http.ResponseWriter, r *http.Request, tenant string, key []byte, token string) {
	value, err := io.ReadAll(io.LimitReader(r.Body, maxStubPlaintextBytes+1))
	if err != nil {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	if int64(len(value)) > maxStubPlaintextBytes {
		writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "object exceeds stub buffer")
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
		Tenant:         tenant,
		Value:          value,
		EncryptionKeys: [][]byte{key},
		Version:        version,
		CreatedAt:      createdAt,
		PartSize:       defaultPartSize,
	})
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *Store) getObject(w http.ResponseWriter, tenant string, key []byte, token string) {
	item, ok := s.Item(token)
	if !ok || item.Tenant != tenant {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "object not found")
		return
	}
	match := false
	for _, k := range item.EncryptionKeys {
		if bytes.Equal(k, key) {
			match = true
			break
		}
	}
	if !match {
		writeS3Error(w, http.StatusBadRequest, "DecryptionFailed", "the provided encryption key cannot decrypt this object")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(item.Value)
}

func (s *Store) deleteObject(w http.ResponseWriter, tenant, token string) {
	s.mu.Lock()
	if item, ok := s.items[token]; ok && item.Tenant == tenant {
		delete(s.items, token)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func resolveTenant(w http.ResponseWriter, r *http.Request) (tenant string, key []byte, ok bool) {
	tenant = r.Header.Get(headerTenantID)
	if tenant == "" || !tenantIDPattern.MatchString(tenant) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "missing or invalid "+headerTenantID)
		return "", nil, false
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get(headerEncryptionKey))
	if err != nil || len(key) != encryptionKeySize {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "missing or invalid "+headerEncryptionKey)
		return "", nil, false
	}
	return tenant, key, true
}

func cloneItem(item Item) Item {
	cp := Item{
		Tenant:         item.Tenant,
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

type s3Error struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func writeS3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(s3Error{Code: code, Message: message})
}
