package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	NonceSize = 12
	TagSize   = 16
)

var ErrCipher = errors.New("aes-gcm: cipher operation failed")

// RandomKey returns a fresh cryptographically-random 32-byte key. It is
// used to mint per-message data keys (DEKs) that the envelope layer seals
// the payload under before wrapping the DEK with the user's CEK.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	if len(nonce) != NonceSize {
		return nil, ErrCipher
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
