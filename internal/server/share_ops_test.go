package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestShareSealOpenRoundTrip(t *testing.T) {
	plaintext := []byte("hello, this is a shared chat with some content")

	sealResp, err := ShareSeal(context.Background(), Deps{}, Session{}, ShareSealRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !sealResp.OK {
		t.Fatal("expected OK")
	}
	if len(sealResp.ShareKey) != shareKeySize*2 {
		t.Fatalf("share key should be %d hex chars, got %d", shareKeySize*2, len(sealResp.ShareKey))
	}

	openResp, err := ShareOpen(context.Background(), Deps{}, ShareOpenRequest{
		ShareKey:   sealResp.ShareKey,
		Ciphertext: sealResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(openResp.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestShareOpenRejectsWrongKey(t *testing.T) {
	sealResp, err := ShareSeal(context.Background(), Deps{}, Session{}, ShareSealRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip one nibble in the share key.
	bad := []byte(sealResp.ShareKey)
	if bad[0] == 'a' {
		bad[0] = 'b'
	} else {
		bad[0] = 'a'
	}
	_, err = ShareOpen(context.Background(), Deps{}, ShareOpenRequest{
		ShareKey:   string(bad),
		Ciphertext: sealResp.Ciphertext,
	})
	if err == nil {
		t.Fatal("expected open with wrong key to fail")
	}
	if appErr, ok := err.(*AppError); !ok || !strings.Contains(appErr.Message, "share decrypt failed") {
		t.Fatalf("unexpected error: %T %v", err, err)
	}
}

func TestShareOpenRejectsTamperedCiphertext(t *testing.T) {
	sealResp, err := ShareSeal(context.Background(), Deps{}, Session{}, ShareSealRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte("payload to tamper with")),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealResp.Ciphertext)
	if err != nil {
		t.Fatalf("decode seal ciphertext: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	_, err = ShareOpen(context.Background(), Deps{}, ShareOpenRequest{
		ShareKey:   sealResp.ShareKey,
		Ciphertext: tampered,
	})
	if err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestShareSealGzipsPlaintext(t *testing.T) {
	// Build a highly compressible input so we can be confident gzip
	// is in the pipeline: a 2 KiB string of one repeating byte.
	plaintext := make([]byte, 2048)
	for i := range plaintext {
		plaintext[i] = 'A'
	}
	sealResp, err := ShareSeal(context.Background(), Deps{}, Session{}, ShareSealRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sealResp.Ciphertext)
	// AES-GCM overhead is 12 (IV) + 16 (tag) = 28 bytes; if the
	// inner stream were not compressed we'd see at least 2048+28.
	if len(raw) > 256 {
		t.Fatalf("expected gzip to compress a highly-redundant payload; got %d bytes", len(raw))
	}
}

func TestShareOpenRejectsOversizedDecompressedPlaintext(t *testing.T) {
	// Hand-craft a small ciphertext whose decompressed payload would
	// overflow shareMaxPlaintextBytes. Sealing 32 MiB of redundant
	// bytes through ShareSeal works but burns 100+ MiB of transient
	// allocations on every test run; this path stays under a few KiB
	// while still hitting the gunzip cap.
	key := make([]byte, shareKeySize)
	rand.Read(key)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("A"), 64<<10)
	written := 0
	for written <= shareMaxPlaintextBytes {
		n, err := gz.Write(chunk)
		if err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		written += n
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	ciphertext, err := seal(key, buf.Bytes())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, err = ShareOpen(context.Background(), Deps{}, ShareOpenRequest{
		ShareKey:   hex.EncodeToString(key),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err == nil {
		t.Fatal("expected oversized share plaintext to fail")
	}
	appErr, ok := err.(*AppError)
	if !ok || appErr.Status != 400 || appErr.Code != CodeBadRequest {
		t.Fatalf("unexpected error: %T %v", err, err)
	}
}
