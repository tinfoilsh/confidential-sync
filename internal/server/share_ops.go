package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
const shareKeySize = 32

// shareIVSize is the AES-GCM nonce length used for share envelopes.
const shareIVSize = 12

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
		return nil, &AppError{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "seal: " + err.Error()}
	}

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

	compressed, err := open(key, ct)
	if err != nil {
		return nil, &AppError{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: "share decrypt failed"}
	}
	defer cryptopkg.Zero(compressed)

	plaintext, err := gunzipBytes(compressed)
	if err != nil {
		return nil, &AppError{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: "share decompress failed"}
	}
	defer cryptopkg.Zero(plaintext)

	return &ShareOpenResponse{
		OK:        true,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

// seal returns [12B IV || AES-GCM ciphertext(plaintext, IV, no AAD)].
// Format matches the on-the-wire layout the webapp recipient expects.
func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, shareIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	out := make([]byte, 0, shareIVSize+len(plaintext)+aead.Overhead())
	out = append(out, iv...)
	out = aead.Seal(out, iv, plaintext, nil)
	return out, nil
}

// open inverts seal(); returns the plaintext.
func open(key, blob []byte) ([]byte, error) {
	if len(blob) < shareIVSize+1 {
		return nil, errors.New("share: ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := blob[:shareIVSize]
	return aead.Open(nil, iv, blob[shareIVSize:], nil)
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
	return io.ReadAll(r)
}
