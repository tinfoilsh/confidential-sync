package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// shareKeySize is the length of the randomly-generated AES-256 key
// the enclave produces per share. Independent of the user's CEK.
// Aliased to cryptopkg.KeySize so any drift in the AES-GCM primitive
// shape lands here automatically.
const shareKeySize = cryptopkg.KeySize

// shareIVSize is the AES-GCM nonce length used for share envelopes,
// taken from the shared crypto primitive so seal() and open() never
// disagree with the rest of the codebase about nonce layout.
const shareIVSize = cryptopkg.NonceSize

// shareMaxPlaintextBytes caps decompressed share plaintext returned by
// /v1/share/open. The encrypted request body is capped separately by
// MaxRequestBytes, but gzip expansion happens after decrypt.
const shareMaxPlaintextBytes = 32 << 20

// ShareSealRequest carries the plaintext the owner wants to share.
// The enclave generates a fresh random key, gzip-then-AES-GCM-seals
// the plaintext, and returns the ciphertext + key. The owner uploads
// the ciphertext to controlplane via /api/shares/:chatId and embeds
// the key in the share URL fragment.
type ShareSealRequest struct {
	Plaintext string `json:"plaintext"` // base64
}

// ShareSealResponse returns the freshly minted share key + the
// sealed ciphertext. The key is hex so it survives URL fragments
// cleanly without padding concerns; the ciphertext is base64 so it
// can be uploaded as JSON or written into an octet-stream upload.
type ShareSealResponse struct {
	OK         bool   `json:"ok"`
	ShareKey   string `json:"share_key"`  // hex 32 bytes
	Ciphertext string `json:"ciphertext"` // base64; [12B IV][AES-GCM ct]
}

// ShareOpenRequest is the recipient's POST body: ciphertext fetched
// from controlplane and the share key from the URL fragment.
type ShareOpenRequest struct {
	ShareKey   string `json:"share_key"`  // hex 32 bytes
	Ciphertext string `json:"ciphertext"` // base64; same shape as seal output
}

// ShareOpenResponse returns the decoded plaintext.
type ShareOpenResponse struct {
	OK        bool   `json:"ok"`
	Plaintext string `json:"plaintext"` // base64
}

// ShareSeal generates a fresh share key, gzips, AES-GCM-seals, and
// returns the result. Called by the owner during share creation.
// Authenticated: the owner must be a real user, but the seal uses
// only the random share key — no CEK material is involved.
func ShareSeal(ctx context.Context, deps Deps, sess Session, req ShareSealRequest) (*ShareSealResponse, error) {
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)
	deps.logInfo("share seal begin: user=%s plaintext_bytes=%d",
		sess.Claims.Subject, len(plaintext))
	// Mirror ShareOpen's decompression cap at seal time; otherwise
	// this endpoint can mint shares that ShareOpen will then always
	// reject as oversized, which is a silent footgun for the caller.
	if len(plaintext) > shareMaxPlaintextBytes {
		return nil, badRequest("plaintext exceeds share size limit")
	}

	compressed, err := gzipBytes(plaintext)
	if err != nil {
		return nil, &AppError{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "gzip: " + err.Error()}
	}
	defer cryptopkg.Zero(compressed)

	key := make([]byte, shareKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, &AppError{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "rand: " + err.Error()}
	}
	defer cryptopkg.Zero(key)

	ct, err := seal(key, compressed)
	if err != nil {
		deps.logError("share seal failed: user=%s err=%v",
			sess.Claims.Subject, err)
		return nil, &AppError{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "seal: " + err.Error()}
	}
	deps.logInfo("share seal ok: user=%s ciphertext_bytes=%d",
		sess.Claims.Subject, len(ct))

	return &ShareSealResponse{
		OK:         true,
		ShareKey:   hex.EncodeToString(key),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// ShareOpen decrypts a share ciphertext with the supplied key and
// returns plaintext. Called by recipients; this op is intentionally
// not authenticated (anyone with the share key can open).
func ShareOpen(ctx context.Context, deps Deps, req ShareOpenRequest) (*ShareOpenResponse, error) {
	key, err := decodeHexKey(req.ShareKey)
	if err != nil {
		return nil, badRequest("invalid share key: " + err.Error())
	}
	defer cryptopkg.Zero(key)

	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, badRequest("invalid ciphertext base64")
	}

	deps.logInfo("share open begin: ciphertext_bytes=%d", len(ct))

	compressed, err := open(key, ct)
	if err != nil {
		deps.logError("share open decrypt failed: err=%v", err)
		return nil, &AppError{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: "share decrypt failed"}
	}
	defer cryptopkg.Zero(compressed)

	plaintext, err := gunzipBytes(compressed)
	if err != nil {
		deps.logError("share open decompress failed: err=%v", err)
		return nil, &AppError{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: "share decompress failed"}
	}
	defer cryptopkg.Zero(plaintext)

	deps.logInfo("share open ok: plaintext_bytes=%d", len(plaintext))

	return &ShareOpenResponse{
		OK:        true,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

// seal returns [12B IV || AES-GCM ciphertext(plaintext, IV, no AAD)].
// Format matches the on-the-wire layout the webapp recipient expects.
// Wraps `cryptopkg.Seal` (the shared AES-256-GCM primitive used by
// the envelope package) so this file does not maintain a private copy
// of the cipher setup — drift in security-critical code is the
// reason we centralise here.
func seal(key, plaintext []byte) ([]byte, error) {
	nonce, ct, err := cryptopkg.Seal(key, plaintext, nil)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// open inverts seal(); returns the plaintext. Wraps `cryptopkg.Open`
// for the same reason seal() wraps cryptopkg.Seal. Any real
// AES-GCM ciphertext is at least TagSize bytes (the authentication
// tag is appended unconditionally), so the minimum legal blob is
// IV + TagSize; anything shorter cannot have come from seal().
func open(key, blob []byte) ([]byte, error) {
	if len(blob) < shareIVSize+cryptopkg.TagSize {
		return nil, errors.New("share: ciphertext too short")
	}
	iv := blob[:shareIVSize]
	return cryptopkg.Open(key, iv, blob[shareIVSize:], nil)
}

func decodeHexKey(s string) ([]byte, error) {
	if len(s) != shareKeySize*2 {
		return nil, fmt.Errorf("expected %d hex chars, got %d", shareKeySize*2, len(s))
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid hex in share key")
	}
	return out, nil
}

func gzipBytes(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipBytes(in []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	limited := io.LimitReader(r, shareMaxPlaintextBytes+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		// out may already hold partially-decompressed plaintext;
		// zero it before surfacing the error so the bytes don't
		// linger in memory until GC.
		cryptopkg.Zero(out)
		return nil, err
	}
	if len(out) > shareMaxPlaintextBytes {
		cryptopkg.Zero(out)
		return nil, errors.New("share: decompressed plaintext exceeds limit")
	}
	return out, nil
}
