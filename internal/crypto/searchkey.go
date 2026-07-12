package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Search-index key derivation.
//
// The per-user search index is stored through the buckets sidecar,
// which seals every object under a caller-supplied AES-256 key. The
// enclave derives that key from the user's CEK so the index inherits
// the CEK's confidentiality without persisting any new key material:
//
//	K_search = HKDF-SHA-256(IKM=CEK, salt="", info="tinfoil-search-index-v1", L=32)

const (
	searchIndexKeyInfo = "tinfoil-search-index-v1"

	searchIndexKeySize = 32
)

var ErrSearchKeyMaterial = errors.New("search-key: CEK must be exactly 32 bytes")

// DeriveSearchIndexKey derives the search-index subkey from the
// user's CEK. Callers MUST zero the returned slice when done.
func DeriveSearchIndexKey(cek []byte) ([]byte, error) {
	if len(cek) != KeySize {
		return nil, ErrSearchKeyMaterial
	}
	out := make([]byte, searchIndexKeySize)
	r := hkdf.New(sha256.New, cek, nil, []byte(searchIndexKeyInfo))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
