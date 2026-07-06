package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveSearchIndexKey(t *testing.T) {
	cekA := bytes.Repeat([]byte{1}, KeySize)
	cekB := bytes.Repeat([]byte{2}, KeySize)

	keyA1, err := DeriveSearchIndexKey(cekA)
	if err != nil {
		t.Fatal(err)
	}
	keyA2, err := DeriveSearchIndexKey(cekA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA1, keyA2) {
		t.Fatal("derivation is not deterministic")
	}
	if len(keyA1) != KeySize {
		t.Fatalf("derived key is %d bytes, want %d", len(keyA1), KeySize)
	}
	if bytes.Equal(keyA1, cekA) {
		t.Fatal("derived key must differ from the CEK itself")
	}

	keyB, err := DeriveSearchIndexKey(cekB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA1, keyB) {
		t.Fatal("different CEKs derived the same index key")
	}

	for _, bad := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, KeySize-1), bytes.Repeat([]byte{1}, KeySize+1)} {
		if _, err := DeriveSearchIndexKey(bad); err != ErrSearchKeyMaterial {
			t.Fatalf("CEK of %d bytes: expected ErrSearchKeyMaterial, got %v", len(bad), err)
		}
	}
}
