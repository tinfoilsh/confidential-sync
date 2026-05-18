package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestAttachmentAAD_StableAndScoped(t *testing.T) {
	a, err := AttachmentAAD("user_1", "chat_1", "att_1")
	if err != nil {
		t.Fatalf("aad: %v", err)
	}
	b, err := AttachmentAAD("user_1", "chat_1", "att_1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("expected canonical AAD to be deterministic for the same tuple")
	}
	c, _ := AttachmentAAD("user_2", "chat_1", "att_1")
	if bytes.Equal(a, c) {
		t.Fatal("different users must produce distinct AAD")
	}
	d, _ := AttachmentAAD("user_1", "chat_2", "att_1")
	if bytes.Equal(a, d) {
		t.Fatal("different chats must produce distinct AAD")
	}
}

func TestSealOpenAttachment_RoundTrip(t *testing.T) {
	cek := bytes.Repeat([]byte{0x42}, KeySize)
	pt := []byte("hello attachment world")
	aad, _ := AttachmentAAD("u", "c", "att")
	blob, err := SealAttachment(cek, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(blob) <= AttachmentIVSize {
		t.Fatalf("blob is shorter than the IV: %d", len(blob))
	}
	got, err := OpenAttachment(cek, blob, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, pt)
	}
}

func TestOpenAttachment_RejectsWrongAAD(t *testing.T) {
	cek := bytes.Repeat([]byte{0x11}, KeySize)
	pt := []byte("body")
	aad, _ := AttachmentAAD("u", "c", "att")
	blob, err := SealAttachment(cek, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := AttachmentAAD("u", "c", "different-att")
	if _, err := OpenAttachment(cek, blob, wrong); err == nil {
		t.Fatal("expected open to fail with the wrong AAD")
	}
}

func TestSealAttachment_RejectsShortKey(t *testing.T) {
	if _, err := SealAttachment(make([]byte, 16), []byte("x"), nil); err == nil {
		t.Fatal("expected error for short cek")
	}
}

func TestOpenAttachment_RejectsShortBlob(t *testing.T) {
	cek := make([]byte, KeySize)
	if _, err := OpenAttachment(cek, []byte("tiny"), nil); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected too-short error, got %v", err)
	}
}
