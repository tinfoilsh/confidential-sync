package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// AttachmentIVSize is the AES-GCM nonce length used by the v2
// attachment envelope. 12 bytes matches the standard GCM nonce size
// and the legacy webapp format so callers see one consistent shape.
const AttachmentIVSize = 12

// attachmentAADDomain tags the canonical JSON the enclave builds for
// each attachment ciphertext. Distinct from the chat envelope's
// domain so an attachment ciphertext can never be replayed as a
// chat blob and vice versa.
const attachmentAADDomain = "tinfoil-attachment-v2"

// AttachmentAAD returns the canonical JSON AAD that binds an
// attachment ciphertext to the user, chat, and attachment id. The
// enclave re-derives the same bytes on Get so a stolen ciphertext
// cannot be moved under a different (user, chat, id) tuple.
func AttachmentAAD(clerkUserID, chatID, attachmentID string) ([]byte, error) {
	if clerkUserID == "" || chatID == "" || attachmentID == "" {
		return nil, errors.New("crypto: attachment aad requires user, chat, id")
	}
	return json.Marshal(struct {
		Domain        string `json:"domain"`
		ClerkUserID   string `json:"clerk_user_id"`
		ChatID        string `json:"chat_id"`
		AttachmentID  string `json:"attachment_id"`
	}{attachmentAADDomain, clerkUserID, chatID, attachmentID})
}

// SealAttachment encrypts plaintext under the user's 32-byte CEK using
// AES-256-GCM with a random 12-byte IV. The output is laid out as
// `IV(12) || ciphertext || tag`, which is the same wire shape the
// legacy webapp emitted — making the bucket bytes self-describing
// without a separate format byte.
func SealAttachment(cek, plaintext, aad []byte) ([]byte, error) {
	if len(cek) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("crypto: attachment cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: attachment gcm: %w", err)
	}
	iv := make([]byte, AttachmentIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("crypto: attachment iv: %w", err)
	}
	ct := gcm.Seal(nil, iv, plaintext, aad)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// OpenAttachment reverses SealAttachment. It expects exactly the
// `IV(12) || ciphertext || tag` layout and returns the plaintext on
// success. A tamper-bit or AAD mismatch surfaces as the standard
// GCM `cipher: message authentication failed` error.
func OpenAttachment(cek, blob, aad []byte) ([]byte, error) {
	if len(cek) != KeySize {
		return nil, ErrKeySize
	}
	if len(blob) < AttachmentIVSize {
		return nil, errors.New("crypto: attachment ciphertext too short")
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("crypto: attachment cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: attachment gcm: %w", err)
	}
	iv := blob[:AttachmentIVSize]
	ct := blob[AttachmentIVSize:]
	return gcm.Open(nil, iv, ct, aad)
}
