package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveAttachmentKey_StableAcrossCalls(t *testing.T) {
	cek := make([]byte, KeySize)
	for i := range cek {
		cek[i] = byte(i)
	}
	a, err := DeriveAttachmentKey(cek, "att-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	b, err := DeriveAttachmentKey(cek, "att-1")
	if err != nil {
		t.Fatalf("derive again: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("expected derivation to be deterministic for same (cek, id)")
	}
}

func TestDeriveAttachmentKey_DistinctIDsGiveDistinctKeys(t *testing.T) {
	cek := make([]byte, KeySize)
	a, _ := DeriveAttachmentKey(cek, "att-1")
	b, _ := DeriveAttachmentKey(cek, "att-2")
	if bytes.Equal(a, b) {
		t.Fatal("expected different attachment ids to give different keys")
	}
}

func TestDeriveAttachmentToken_StableAndDistinct(t *testing.T) {
	cek := make([]byte, KeySize)
	for i := range cek {
		cek[i] = byte(i + 1)
	}
	a, err := DeriveAttachmentToken(cek, "att-1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	b, _ := DeriveAttachmentToken(cek, "att-1")
	if a != b {
		t.Fatal("expected token derivation to be deterministic")
	}
	c, _ := DeriveAttachmentToken(cek, "att-2")
	if a == c {
		t.Fatal("expected different ids to give different tokens")
	}
}

func TestDeriveAttachment_KeyAndTokenAreIndependent(t *testing.T) {
	cek := make([]byte, KeySize)
	for i := range cek {
		cek[i] = byte(i + 2)
	}
	k, _ := DeriveAttachmentKey(cek, "att-1")
	tok, _ := DeriveAttachmentToken(cek, "att-1")
	// Token is hex of 24 bytes => 48 hex chars; cannot equal a 32-byte key.
	if string(k) == tok {
		t.Fatal("expected key and token to be independent values")
	}
}

func TestDeriveAttachmentKey_RejectsBadInputs(t *testing.T) {
	if _, err := DeriveAttachmentKey(make([]byte, 16), "x"); err == nil {
		t.Fatal("expected error for short cek")
	}
	if _, err := DeriveAttachmentKey(make([]byte, KeySize), ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestDeriveAttachmentToken_RejectsBadInputs(t *testing.T) {
	if _, err := DeriveAttachmentToken(make([]byte, 16), "x"); err == nil {
		t.Fatal("expected error for short cek")
	}
	if _, err := DeriveAttachmentToken(make([]byte, KeySize), ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}
