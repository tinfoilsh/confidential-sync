package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Operation-hash construction. See syncplan.md §7.0.
//
// X-Operation-Hash is a keyed MAC, not a plaintext digest. The
// controlplane stores the value in sync_idempotency_keys to detect
// retries and replays, and it sits inside the threat boundary: a plain
// SHA-256(plaintext) would be brute-forceable against low-entropy
// payloads (profile flags, short prompts, common templates). We
// therefore key the MAC on a subkey derived from the user's CEK that
// the controlplane never sees.
//
//	K_op = HKDF-SHA-256(IKM=CEK, salt="", info="tinfoil-op-hash-v1", L=32)
//	X-Operation-Hash = hex(HMAC-SHA-256(K_op, canonical))
//
// The canonical input is a length-prefixed concatenation of the
// auth-relevant fields. Lengths are big-endian uint32. See
// AppendCanonical below for the exact byte layout.

const (
	// opHashInfo is the HKDF info string used to derive the operation
	// hash subkey from the user's CEK. Version-tagged so future
	// protocol changes can be introduced without an ambiguous overlap.
	opHashInfo = "tinfoil-op-hash-v1"

	// opHashKeySize is the length of the derived subkey, in bytes.
	opHashKeySize = 32
)

var ErrOpHashKeyMaterial = errors.New("op-hash: CEK must be exactly 32 bytes")

// DeriveOpHashKey derives the operation-hash subkey from the user's
// CEK. Callers MUST zero the returned slice when done.
func DeriveOpHashKey(cek []byte) ([]byte, error) {
	if len(cek) != KeySize {
		return nil, ErrOpHashKeyMaterial
	}
	out := make([]byte, opHashKeySize)
	r := hkdf.New(sha256.New, cek, nil, []byte(opHashInfo))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// CanonicalInput describes the fields that go into the canonical tuple
// the MAC is computed over. Field semantics match syncplan.md §7.0:
//
//	Method:         "PUT" | "POST" | "DELETE" (uppercase ASCII)
//	Path:           request path incl. query, exactly as sent on the wire
//	KeyIDHex:       32-char lowercase hex key_id
//	IfMatch:        decimal ASCII etag, or the literal header value
//	                ("0" for create, "*" or a hex key for register-key)
//	IdempotencyKey: client-chosen UUID/ULID, ASCII
//	Body:           stable logical body bytes (nil-safe for DELETEs;
//	                plaintext for blob writes so randomized envelopes
//	                do not break idempotent retries)
//	AAD:            canonical AAD bytes used during seal; nil for
//	                non-blob operations (key register / rewrap-by-meta /
//	                share / attachment)
//	Envelope:       optional v2 envelope bytes for callers that need
//	                to bind a specific ciphertext generation
//	ProfileSyncProtocol:
//	                optional profile merge protocol version forwarded
//	                to the controlplane
//
// Blob writes pass plaintext in Body and canonical AAD in AAD. The
// plaintext is protected by a keyed MAC under K_op before it ever
// reaches the controlplane, so low-entropy payloads remain outside
// the controlplane's brute-force boundary while retries stay stable
// across AES-GCM nonce changes.
type CanonicalInput struct {
	Method              string
	Path                string
	KeyIDHex            string
	IfMatch             string
	IdempotencyKey      string
	Body                []byte
	AAD                 []byte
	Envelope            []byte
	ProfileSyncProtocol string
}

// AppendCanonical writes the canonical encoding of the tuple to dst and
// returns the extended slice. Each field is preceded by its length as a
// big-endian uint32. This is the exact byte string the MAC is computed
// over and the same encoding the web client uses.
//
// AAD and Envelope are only appended when at least one is present or
// ProfileSyncProtocol is set.
// Body-only operations (RegisterKey, AddBundle, rewrap, etc.) keep
// the historical encoding so cached sync_idempotency_keys entries
// continue to verify after this rollout. Blob mutations carry AAD so
// they unambiguously land on the extended encoding.
func AppendCanonical(dst []byte, in CanonicalInput) []byte {
	dst = appendLenPrefixed(dst, []byte(in.Method))
	dst = appendLenPrefixed(dst, []byte(in.Path))
	dst = appendLenPrefixed(dst, []byte(in.KeyIDHex))
	dst = appendLenPrefixed(dst, []byte(in.IfMatch))
	dst = appendLenPrefixed(dst, []byte(in.IdempotencyKey))
	dst = appendLenPrefixed(dst, in.Body)
	if in.AAD != nil || in.Envelope != nil || in.ProfileSyncProtocol != "" {
		dst = appendLenPrefixed(dst, in.AAD)
		dst = appendLenPrefixed(dst, in.Envelope)
	}
	if in.ProfileSyncProtocol != "" {
		dst = appendLenPrefixed(dst, []byte(in.ProfileSyncProtocol))
	}
	return dst
}

func appendLenPrefixed(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, b...)
	return dst
}

// ComputeOperationHash returns the hex-encoded HMAC for the given
// canonical input, using a subkey already derived by DeriveOpHashKey.
func ComputeOperationHash(opKey []byte, in CanonicalInput) string {
	mac := hmac.New(sha256.New, opKey)
	mac.Write(AppendCanonical(nil, in))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum)
}

// VerifyOperationHash returns true if `provided` is the correct
// hex-encoded HMAC for `in` under the subkey derived from `cek`.
// Comparison is constant-time.
func VerifyOperationHash(cek []byte, provided string, in CanonicalInput) (bool, error) {
	opKey, err := DeriveOpHashKey(cek)
	if err != nil {
		return false, err
	}
	defer Zero(opKey)

	want, err := hex.DecodeString(provided)
	if err != nil || len(want) != sha256.Size {
		return false, nil
	}
	mac := hmac.New(sha256.New, opKey)
	mac.Write(AppendCanonical(nil, in))
	return hmac.Equal(mac.Sum(nil), want), nil
}
