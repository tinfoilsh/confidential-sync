package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize    = 32
	KeyIDSize  = 16
	keyIDInfo  = "tinfoil-key-id-v1"
	bundleInfo = "tinfoil-key-bundle-v2"
)

var (
	ErrKeySize   = errors.New("key must be exactly 32 bytes")
	ErrKeyIDSize = errors.New("key_id must be exactly 16 bytes")
)

func DeriveKeyID(key []byte) ([KeyIDSize]byte, error) {
	var out [KeyIDSize]byte
	if len(key) != KeySize {
		return out, ErrKeySize
	}
	r := hkdf.New(sha256.New, key, nil, []byte(keyIDInfo))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

func KeyIDHex(id [KeyIDSize]byte) string {
	return hex.EncodeToString(id[:])
}

func ParseKeyIDHex(s string) ([KeyIDSize]byte, error) {
	var out [KeyIDSize]byte
	if len(s) != KeyIDSize*2 {
		return out, ErrKeyIDSize
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
