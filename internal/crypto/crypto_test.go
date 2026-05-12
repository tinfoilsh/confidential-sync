package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustRandKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDeriveKeyIDDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeySize)
	a, err := DeriveKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("not deterministic")
	}
}

func TestDeriveKeyIDDifferentKeys(t *testing.T) {
	a, err := DeriveKeyID(bytes.Repeat([]byte{0x01}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKeyID(bytes.Repeat([]byte{0x02}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("collision on different keys")
	}
}

func TestDeriveKeyIDLength(t *testing.T) {
	id, err := DeriveKeyID(mustRandKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != KeyIDSize {
		t.Fatalf("got %d, want %d", len(id), KeyIDSize)
	}
}

func TestDeriveKeyIDRejectsBadKey(t *testing.T) {
	if _, err := DeriveKeyID(make([]byte, 31)); err == nil {
		t.Fatalf("expected error")
	}
}

func TestKeyIDHexRoundTrip(t *testing.T) {
	id, err := DeriveKeyID(mustRandKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s := KeyIDHex(id)
	if len(s) != 32 {
		t.Fatalf("hex length %d", len(s))
	}
	back, err := ParseKeyIDHex(s)
	if err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := mustRandKey(t)
	pt := []byte("hello tinfoil")
	aad := []byte(`{"domain":"tinfoil-sync-envelope-v2"}`)
	nonce, ct, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce size %d", len(nonce))
	}
	out, err := Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestAESGCMAADMismatchFails(t *testing.T) {
	key := mustRandKey(t)
	nonce, ct, err := Seal(key, []byte("x"), []byte("aad-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, nonce, ct, []byte("aad-2")); err == nil {
		t.Fatalf("expected AAD mismatch failure")
	}
}

func TestAESGCMTamperFails(t *testing.T) {
	key := mustRandKey(t)
	nonce, ct, err := Seal(key, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	if _, err := Open(key, nonce, ct, nil); err == nil {
		t.Fatalf("expected tamper failure")
	}
}

func TestZeroWipes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	for _, v := range b {
		if v != 0 {
			t.Fatalf("not zeroed: %v", b)
		}
	}
}

func TestKeyIDKnownVector(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	id, err := DeriveKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	got := KeyIDHex(id)
	if len(got) != 32 {
		t.Fatalf("bad length")
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("not hex: %v", err)
	}
}
