package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// attachmentKeyInfo is the HKDF info string that produces the
// per-attachment AES-256 key the enclave hands to buckets.tinfoil.sh.
// Distinct from attachmentTokenInfo so the two HKDF outputs are
// independent.
const attachmentKeyInfo = "attachment-key|"

// attachmentTokenInfo is the HKDF info string that produces the
// per-attachment access token (the buckets URL path). Path tokens
// must be opaque to the buckets server: knowing the token is the
// only proof of ownership of the slot, so they must be unguessable
// across users. Deriving them from the user's CEK guarantees that.
const attachmentTokenInfo = "attachment-token|"

// AttachmentTokenSize is the number of HKDF bytes used to form the
// access token. 24 raw bytes encode to 48 hex chars, well inside
// the buckets [36..76] charset window.
const AttachmentTokenSize = 24

// DeriveAttachmentKey returns the 32-byte AES-256 key the sync
// enclave hands to buckets when sealing the named attachment. Each
// (CEK, attachmentID) pair maps to a unique key so a compromised key
// only ever reveals one attachment's bytes.
func DeriveAttachmentKey(cek []byte, attachmentID string) ([]byte, error) {
	if len(cek) != KeySize {
		return nil, ErrKeySize
	}
	if attachmentID == "" {
		return nil, errors.New("crypto: attachment id is required")
	}
	r := hkdf.New(sha256.New, cek, nil, []byte(attachmentKeyInfo+attachmentID))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveAttachmentToken returns the opaque access token the sync
// enclave uses as the buckets URL path for the named attachment.
// The token is a hex-encoded HKDF output keyed by the CEK so that
// across users tokens are unguessable and across rotations the
// same (CEK, id) pair always resolves to the same slot.
func DeriveAttachmentToken(cek []byte, attachmentID string) (string, error) {
	if len(cek) != KeySize {
		return "", ErrKeySize
	}
	if attachmentID == "" {
		return "", errors.New("crypto: attachment id is required")
	}
	r := hkdf.New(sha256.New, cek, nil, []byte(attachmentTokenInfo+attachmentID))
	raw := make([]byte, AttachmentTokenSize)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
