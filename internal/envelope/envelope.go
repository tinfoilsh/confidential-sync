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
	Alg string `json:"alg"`
	// KID identifies the CEK that wrapped the data key (WDEK), not the
	// key the payload is sealed under. It selects which key unwraps the
	// data key on read and is the single field a CEK rotation rewrites.
	KID string `json:"kid"`
	// WDEK is the per-message data key sealed under the CEK
	// (AES-256-GCM ciphertext+tag, base64). WIV is its 12-byte nonce, hex.
	WDEK string `json:"wdek"`
	WIV  string `json:"wiv"`
	// IV / CT are the payload nonce (hex) and the gzipped plaintext
	// sealed under the data key (AES-256-GCM ciphertext+tag, base64).
	IV string `json:"iv"`
	CT string `json:"ct"`
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

// Detect classifies a ciphertext blob by attempting strict parses
// against each known envelope shape in turn. There is intentionally
// no byte-prefix heuristic: any prefix-based discriminator is
// ambiguous because v1 ciphertext bytes are uniformly random and can
// imitate the opening of a JSON object. Instead we ask the harder
// question "does this parse as a fully-formed v2 / v0 envelope?" and
// fall back to v1 only when both strict parses fail.
//
//  1. Try parsing as a v2 envelope. v2 requires `"v":2` plus the
//     `kid`, `alg`, `iv`, `ct` fields populated. A real v2 blob
//     always succeeds here; a v1 binary blob has effectively zero
//     probability of being a complete valid v2 JSON document with
//     `"v":2`.
//  2. Try parsing as a v0 envelope. v0 requires `iv` and `data`
//     fields and explicitly forbids a `v` field (otherwise we'd
//     accept v2 as v0 too). Same probabilistic argument as v2.
//  3. Otherwise, if the blob is at least IV+TAG bytes long, treat
//     it as v1. v1 has no version tag on the wire — that's why we
//     cannot do better — but the strict-parse cascade above means
//     we never accidentally route a real v0/v2 blob here.
//
// A truncated or otherwise-malformed v0/v2 envelope fails both
// strict parses and falls through to v1; DecryptLegacy then fails
// to decrypt the malformed bytes and the caller sees a decrypt
// error. That is an unavoidable consequence of v1's lack of a
// wire-level marker; the alternative (returning Unknown on parse
// failure) silently loses real v1 blobs whose random nonce happens
// to start with `{`. We prefer "always recover real v1 data" over
// "produce a slightly more specific error on corruption".
func Detect(blob []byte) Version {
	if len(blob) == 0 {
		return VersionUnknown
	}
	if looksLikeV2(blob) {
		return VersionV2
	}
	if looksLikeV0(blob) {
		return VersionV0
	}
	if len(blob) >= crypto.NonceSize+crypto.TagSize {
		return VersionV1
	}
	return VersionUnknown
}

// looksLikeV2 returns true when blob fully parses as JSON and carries
// the v2 version tag. Field validity (non-empty kid/iv/ct, supported
// alg) is enforced by DecryptV2; Detect's only job is shape
// classification. A partial / truncated JSON document fails the
// strict Unmarshal and is therefore not v2.
//
// The probe struct only captures the `v` field; decoding the full
// V2 struct here would copy the (potentially megabyte-sized) `ct`
// base64 string into a fresh allocation on every Detect call, which
// is wasted work because Detect never inspects it.
func looksLikeV2(blob []byte) bool {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(blob, &probe); err != nil {
		return false
	}
	return probe.V == int(VersionV2)
}

// looksLikeV0 returns true when blob fully parses as JSON in the v0
// legacy shape: `iv` and `data` fields are both present, and the
// `v` field is absent (so v2 envelopes never alias to v0). Empty
// strings are still considered v0-shaped; per-field validity is
// enforced by decryptV0.
func looksLikeV0(blob []byte) bool {
	var probe struct {
		V    *int    `json:"v"`
		IV   *string `json:"iv"`
		Data *string `json:"data"`
	}
	if err := json.Unmarshal(blob, &probe); err != nil {
		return false
	}
	if probe.V != nil {
		return false
	}
	return probe.IV != nil && probe.Data != nil
}

type Key struct {
	Bytes    []byte
	KeyIDHex string // lowercase hex
}

type DecryptResult struct {
	Plaintext   []byte
	KeyIDHex    string
	Version     Version
	NeedsRewrap bool
}

// Encrypt produces a v2 envelope around plaintext. The payload is sealed
// under a fresh random per-message data key (DEK); that DEK is then wrapped
// under the caller's key (the user's CEK, identified by aad.KeyIDHex). The
// caller is responsible for zeroing plaintext after the returned envelope is
// transmitted; the envelope JSON itself contains only ciphertext.
//
// Pipeline: gzip(plaintext) → AES-GCM-Seal(DEK, …) for the payload, and
// AES-GCM-Seal(CEK, DEK, …) for the wrapped key. Splitting the content key
// from the CEK lets a CEK rotation rewrap only the small data key and leave
// the (potentially large) payload ciphertext untouched — which is also why
// the payload AAD is independent of the CEK key id. Compression happens
// before encryption because ciphertext will not compress at any downstream
// layer.
func Encrypt(key []byte, plaintext []byte, aad AAD) ([]byte, error) {
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrKeySize
	}
	payloadAAD, err := CanonicalPayloadAAD(aad)
	if err != nil {
		return nil, err
	}
	wrapAAD, err := CanonicalDEKWrapAAD(aad)
	if err != nil {
		return nil, err
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
	dek, err := crypto.RandomKey()
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(dek)
	payloadIV, payloadCT, err := crypto.Seal(dek, compressed, payloadAAD)
	if err != nil {
		return nil, err
	}
	wrapIV, wrappedDEK, err := crypto.Seal(key, dek, wrapAAD)
	if err != nil {
		return nil, err
	}
	env := V2{
		V:    int(VersionV2),
		Alg:  AlgAESGCM,
		KID:  aad.KeyIDHex,
		WDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		WIV:  hex.EncodeToString(wrapIV),
		IV:   hex.EncodeToString(payloadIV),
		CT:   base64.StdEncoding.EncodeToString(payloadCT),
	}
	return json.Marshal(env)
}

// DecryptV2 parses and decrypts a v2 envelope. The envelope's `kid` selects
// which of the supplied keys unwraps the per-message data key; that data key
// then opens the payload. Only one key is used, so the operation is
// constant-cost. `aad` supplies the scope/id/clerk_user_id the two AAD layers
// are rebuilt from; the kid for the wrap AAD comes from the envelope itself.
func DecryptV2(blob []byte, keys []Key, aad AAD) (DecryptResult, error) {
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
	if len(env.IV) != crypto.NonceSize*2 || len(env.WIV) != crypto.NonceSize*2 {
		return DecryptResult{}, ErrV2Malformed
	}
	iv, err := hex.DecodeString(env.IV)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	wrapIV, err := hex.DecodeString(env.WIV)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	// Both `ct` (payload) and `wdek` (wrapped data key) must be
	// exact-canonical RFC 4648 standard base64: only the 64-char
	// alphabet plus `=` padding at the tail, and no non-zero "spare"
	// bits in the final group. The canonical form is necessary because
	// two different aspects of a permissive decoder both produce
	// equal-decoded-bytes-different-wire-bytes ambiguity:
	//
	//   1. Spare bits in the last data char of a 1- or 2-pad
	//      group (`XXXY=` and `XXXZ=` decode identically when Y
	//      and Z differ only in their low 2 or 4 bits).
	//   2. Embedded whitespace — `\n`, `\r` — which `Strict()`
	//      still silently skips, so a tampered JSON envelope
	//      could carry a base64 string with `\n` injected anywhere
	//      and decrypt to the same bytes.
	//
	// `Strict()` catches (1) but not (2); the explicit alphabet
	// pre-check below catches (2) without an extra allocation.
	if !isCanonicalStdBase64(env.CT) || !isCanonicalStdBase64(env.WDEK) {
		return DecryptResult{}, ErrV2Malformed
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(env.CT)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	wrappedDEK, err := base64.StdEncoding.Strict().DecodeString(env.WDEK)
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
	wrapAAD, err := CanonicalDEKWrapAAD(AAD{
		KeyIDHex:    env.KID,
		Scope:       aad.Scope,
		ID:          aad.ID,
		ClerkUserID: aad.ClerkUserID,
	})
	if err != nil {
		return DecryptResult{}, err
	}
	dek, err := crypto.Open(match.Bytes, wrapIV, wrappedDEK, wrapAAD)
	if err != nil {
		return DecryptResult{}, err
	}
	defer crypto.Zero(dek)
	// The authenticated unwrap proves the DEK bytes are exactly what was
	// sealed, so a wrong length signals a broken seal-side invariant rather
	// than tampering. Fail closed with a specific error here instead of
	// letting the payload open below surface a generic key-size error.
	if len(dek) != crypto.KeySize {
		return DecryptResult{}, ErrV2Malformed
	}
	payloadAAD, err := CanonicalPayloadAAD(aad)
	if err != nil {
		return DecryptResult{}, err
	}
	compressed, err := crypto.Open(dek, iv, ct, payloadAAD)
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
//
//	IV(12) || AES-GCM-ciphertext(gzip(JSON))
//
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
		defer crypto.Zero(compressed)
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

// isCanonicalStdBase64 returns true when s consists only of
// standard-base64 alphabet characters (A-Z, a-z, 0-9, +, /) with
// zero, one, or two `=` characters at the tail, and the total
// length is a non-zero multiple of 4.
//
// This is an alphabet-and-shape check, not a value check; combined
// with base64.StdEncoding.Strict().DecodeString it forbids both
// non-canonical spare-bit endings and embedded whitespace
// (\n, \r, ' ', \t) that the stdlib decoder otherwise tolerates.
// Both forms would let two distinct wire-level `ct` strings
// produce the same decoded ciphertext, which is a tampering
// ambiguity we want to surface as ErrV2Malformed instead of
// silently accepting either spelling.
func isCanonicalStdBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	end := len(s)
	pad := 0
	if s[end-1] == '=' {
		pad++
		if s[end-2] == '=' {
			pad++
		}
	}
	for i := 0; i < end-pad; i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '+', c == '/':
		default:
			return false
		}
	}
	return true
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
