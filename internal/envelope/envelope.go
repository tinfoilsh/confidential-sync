package envelope

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

type Version int

const (
	VersionUnknown Version = 0
	VersionV0      Version = -1 // legacy JSON {iv, data}
	VersionV1      Version = -2 // legacy binary gzip(AES-GCM(...))
	VersionV2      Version = 2
)

type V2 struct {
	V   int    `json:"v"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

type legacyV0 struct {
	IV   string `json:"iv"`
	Data string `json:"data"`
}

const (
	// Upper bound on decompressed plaintext. Applies to v1 legacy blobs
	// (the original cap) and v2 envelopes now that v2 carries gzipped
	// plaintext as well.
	maxDecompressedBytes = 32 * 1024 * 1024
)

var (
	ErrUnknownFormat   = errors.New("envelope: unknown format")
	ErrV2Malformed     = errors.New("envelope: malformed v2")
	ErrV0Malformed     = errors.New("envelope: malformed legacy v0")
	ErrV1Malformed     = errors.New("envelope: malformed legacy v1")
	ErrNoMatchingKey   = errors.New("envelope: no key matches kid")
	ErrLegacyDecrypt   = errors.New("envelope: no provided key decrypted legacy blob")
	ErrUnsupportedAlg  = errors.New("envelope: unsupported algorithm")
	ErrInvalidEnvelope = errors.New("envelope: invalid envelope")
)

// Detect classifies a ciphertext blob by inspecting its prefix.
// v2 envelopes are JSON objects starting with `{` and containing `"v":2`.
// v0 legacy is JSON with iv+data and no v field.
// v1 legacy is raw binary `IV(12) || AES-GCM-ciphertext(gzip(JSON))` as
// produced by the webapp's `compressAndEncrypt` (binary-codec.ts). The
// first byte is a random IV byte, so anything that is not a JSON object
// and is long enough to carry an IV + GCM tag is treated as v1.
func Detect(blob []byte) Version {
	if len(blob) == 0 {
		return VersionUnknown
	}
	trimmed := bytes.TrimLeft(blob, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var probe struct {
			V  *int    `json:"v"`
			IV *string `json:"iv"`
		}
		if err := json.Unmarshal(trimmed, &probe); err == nil {
			if probe.V != nil && *probe.V == int(VersionV2) {
				return VersionV2
			}
			if probe.IV != nil {
				return VersionV0
			}
		}
		return VersionUnknown
	}
	if len(blob) >= crypto.NonceSize+crypto.TagSize {
		return VersionV1
	}
	return VersionUnknown
}

type Key struct {
	Bytes     []byte
	KeyIDHex  string // lowercase hex
}

type DecryptResult struct {
	Plaintext   []byte
	KeyIDHex    string
	Version     Version
	NeedsRewrap bool
}

// Encrypt produces a v2 envelope around plaintext using key+AAD. The caller
// is responsible for zeroing plaintext after the returned envelope is
// transmitted; the envelope JSON itself contains only ciphertext.
//
// Pipeline: gzip(plaintext) → AES-GCM-Seal(...) → v2 envelope.
// Compression happens before encryption because ciphertext is random and
// will not compress further at any downstream layer.
func Encrypt(key []byte, plaintext, aad []byte, keyIDHex string) ([]byte, error) {
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrKeySize
	}
	if len(keyIDHex) != 32 || !isLowerHex(keyIDHex) {
		return nil, ErrInvalidEnvelope
	}
	// Reject plaintexts that won't fit under the decompress cap.
	// Without this check a write can succeed at seal time and then
	// fail every subsequent decrypt — turning oversized inputs into
	// silent data loss instead of an immediate, actionable error.
	if len(plaintext) > maxDecompressedBytes {
		return nil, ErrInvalidEnvelope
	}
	compressed, err := gzipBytes(plaintext)
	if err != nil {
		return nil, err
	}
	// The compressed buffer holds a transformed copy of the
	// plaintext until ciphertext is produced; zero it on the way
	// out so we don't leave plaintext-derived material lying in
	// enclave memory longer than necessary.
	defer crypto.Zero(compressed)
	nonce, ct, err := crypto.Seal(key, compressed, aad)
	if err != nil {
		return nil, err
	}
	env := V2{
		V:   int(VersionV2),
		KID: keyIDHex,
		Alg: AlgAESGCM,
		IV:  hex.EncodeToString(nonce),
		CT:  base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// DecryptV2 parses and decrypts a v2 envelope. The supplied keys are tried
// by matching `kid`; only one key is used so the operation is constant-cost.
func DecryptV2(blob []byte, keys []Key, aadFor func(keyIDHex string) ([]byte, error)) (DecryptResult, error) {
	var env V2
	if err := json.Unmarshal(blob, &env); err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	if env.V != int(VersionV2) {
		return DecryptResult{}, ErrV2Malformed
	}
	if env.Alg != AlgAESGCM {
		return DecryptResult{}, ErrUnsupportedAlg
	}
	if len(env.KID) != 32 || !isLowerHex(env.KID) {
		return DecryptResult{}, ErrV2Malformed
	}
	if len(env.IV) != crypto.NonceSize*2 {
		return DecryptResult{}, ErrV2Malformed
	}
	iv, err := hex.DecodeString(env.IV)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	var match *Key
	for i := range keys {
		if keys[i].KeyIDHex == env.KID {
			match = &keys[i]
			break
		}
	}
	if match == nil {
		return DecryptResult{KeyIDHex: env.KID}, ErrNoMatchingKey
	}
	aad, err := aadFor(env.KID)
	if err != nil {
		return DecryptResult{}, err
	}
	compressed, err := crypto.Open(match.Bytes, iv, ct, aad)
	if err != nil {
		return DecryptResult{}, err
	}
	defer crypto.Zero(compressed)
	pt, err := gunzip(compressed)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	return DecryptResult{
		Plaintext:   pt,
		KeyIDHex:    env.KID,
		Version:     VersionV2,
		NeedsRewrap: false,
	}, nil
}

// DecryptLegacy attempts each provided key against a v0 or v1 blob. Legacy
// blobs were written without AAD; the caller passes nil to keep semantics
// identical to the original clients. NeedsRewrap is always true on success.
func DecryptLegacy(blob []byte, keys []Key) (DecryptResult, error) {
	switch Detect(blob) {
	case VersionV0:
		return decryptV0(blob, keys)
	case VersionV1:
		return decryptV1(blob, keys)
	}
	return DecryptResult{}, ErrUnknownFormat
}

func decryptV0(blob []byte, keys []Key) (DecryptResult, error) {
	var raw legacyV0
	if err := json.Unmarshal(blob, &raw); err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV0Malformed, err)
	}
	if raw.IV == "" || raw.Data == "" {
		return DecryptResult{}, ErrV0Malformed
	}
	iv, err := decodeBase64OrHex(raw.IV, crypto.NonceSize)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV0Malformed, err)
	}
	ct, err := base64.StdEncoding.DecodeString(raw.Data)
	if err != nil {
		// Some legacy clients used base64url without padding.
		ct, err = base64.RawURLEncoding.DecodeString(raw.Data)
		if err != nil {
			return DecryptResult{}, fmt.Errorf("%w: %v", ErrV0Malformed, err)
		}
	}
	for _, k := range keys {
		if len(k.Bytes) != crypto.KeySize {
			continue
		}
		pt, err := crypto.Open(k.Bytes, iv, ct, nil)
		if err == nil {
			return DecryptResult{
				Plaintext:   pt,
				KeyIDHex:    k.KeyIDHex,
				Version:     VersionV0,
				NeedsRewrap: true,
			}, nil
		}
	}
	return DecryptResult{}, ErrLegacyDecrypt
}

// decryptV1 reverses the webapp's `compressAndEncrypt` pipeline:
//   IV(12) || AES-GCM-ciphertext(gzip(JSON))
// We split off the IV, AES-GCM-Open the rest, then gunzip the plaintext.
// Legacy v1 blobs were written without AAD, so callers pass nil here.
func decryptV1(blob []byte, keys []Key) (DecryptResult, error) {
	if len(blob) < crypto.NonceSize+crypto.TagSize {
		return DecryptResult{}, ErrV1Malformed
	}
	iv := blob[:crypto.NonceSize]
	ct := blob[crypto.NonceSize:]
	for _, k := range keys {
		if len(k.Bytes) != crypto.KeySize {
			continue
		}
		compressed, err := crypto.Open(k.Bytes, iv, ct, nil)
		if err != nil {
			continue
		}
		pt, err := gunzip(compressed)
		if err != nil {
			return DecryptResult{}, fmt.Errorf("%w: %v", ErrV1Malformed, err)
		}
		return DecryptResult{
			Plaintext:   pt,
			KeyIDHex:    k.KeyIDHex,
			Version:     VersionV1,
			NeedsRewrap: true,
		}, nil
	}
	return DecryptResult{}, ErrLegacyDecrypt
}

func gzipBytes(plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plaintext); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzip(compressed []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	limited := io.LimitReader(gz, maxDecompressedBytes+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecompressedBytes {
		return nil, errors.New("envelope: decompressed plaintext exceeds limit")
	}
	return out, nil
}

// decodeBase64OrHex accepts both encodings because two production clients
// historically wrote v0 IVs differently. The expected decoded length is
// enforced to avoid silent acceptance of garbage.
func decodeBase64OrHex(s string, want int) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == want {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == want {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == want {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == want {
		return b, nil
	}
	return nil, errors.New("envelope: iv has wrong length or encoding")
}
