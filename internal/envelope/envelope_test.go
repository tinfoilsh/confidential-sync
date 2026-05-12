package envelope

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

func newRawKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, cryptopkg.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newKey(t *testing.T) Key {
	t.Helper()
	raw := newRawKey(t)
	id, err := cryptopkg.DeriveKeyID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Bytes: raw, KeyIDHex: cryptopkg.KeyIDHex(id)}
}

func TestCanonicalAADStable(t *testing.T) {
	a := AAD{
		KeyIDHex:    strings.Repeat("ab", 16),
		Scope:       ScopeChat,
		ID:          "chat_abc",
		ClerkUserID: "user_xyz",
	}
	b1, err := CanonicalAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := CanonicalAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("not stable: %s vs %s", b1, b2)
	}
	want := `{"alg":"AES-256-GCM","clerk_user_id":"user_xyz","domain":"tinfoil-sync-envelope-v2","id":"chat_abc","kid":"abababababababababababababababab","scope":"chat","v":2}`
	if string(b1) != want {
		t.Fatalf("canonical AAD mismatch:\n got:  %s\n want: %s", b1, want)
	}
}

func TestCanonicalAADRejectsInvalid(t *testing.T) {
	cases := []AAD{
		{Scope: "chat", KeyIDHex: "tooShort", ID: "x", ClerkUserID: "u"},
		{Scope: "chat", KeyIDHex: strings.Repeat("a", 32), ID: "x", ClerkUserID: ""},
		{Scope: "chat", KeyIDHex: strings.Repeat("a", 32), ID: "", ClerkUserID: "u"},
		{Scope: "bogus", KeyIDHex: strings.Repeat("a", 32), ID: "x", ClerkUserID: "u"},
		{Scope: "chat", KeyIDHex: strings.Repeat("A", 32), ID: "x", ClerkUserID: "u"},
	}
	for i, c := range cases {
		if _, err := CanonicalAAD(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestCanonicalAADProfileDefaultID(t *testing.T) {
	a := AAD{
		KeyIDHex:    strings.Repeat("c", 32),
		Scope:       ScopeProfile,
		ClerkUserID: "u",
	}
	out, err := CanonicalAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"id":"profile"`) {
		t.Fatalf("profile ID default missing: %s", out)
	}
}

func TestCanonicalBundleAAD(t *testing.T) {
	out, err := CanonicalBundleAAD(BundleAAD{
		ClerkUserID:  "user_1",
		KeyIDHex:     strings.Repeat("0", 32),
		CredentialID: "cred-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"clerk_user_id":"user_1","credential_id":"cred-1","domain":"tinfoil-key-bundle-v2","key_id":"00000000000000000000000000000000"}`
	if string(out) != want {
		t.Fatalf("bundle AAD mismatch:\n got:  %s\n want: %s", out, want)
	}
}

func TestMetadataHashStableAcrossKeyOrder(t *testing.T) {
	a := map[string]any{"a": 1, "b": "two", "c": []any{1.0, 2.0}}
	b := map[string]any{"c": []any{1.0, 2.0}, "b": "two", "a": 1}
	ha, err := MetadataHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := MetadataHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("metadata hash unstable: %s vs %s", ha, hb)
	}
}

func TestV2RoundTrip(t *testing.T) {
	k := newKey(t)
	aad := AAD{
		KeyIDHex:    k.KeyIDHex,
		Scope:       ScopeChat,
		ID:          "chat_1",
		ClerkUserID: "user_a",
	}
	aadBytes, err := CanonicalAAD(aad)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("the quick brown fox")
	blob, err := Encrypt(k.Bytes, pt, aadBytes, k.KeyIDHex)
	if err != nil {
		t.Fatal(err)
	}
	if Detect(blob) != VersionV2 {
		t.Fatalf("detect: %v", Detect(blob))
	}
	res, err := DecryptV2(blob, []Key{k}, func(kid string) ([]byte, error) {
		if kid != k.KeyIDHex {
			t.Fatalf("aadFor called with wrong kid: %s", kid)
		}
		return aadBytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, pt) {
		t.Fatalf("plaintext mismatch")
	}
	if res.NeedsRewrap {
		t.Fatalf("v2 should never need rewrap")
	}
	if res.KeyIDHex != k.KeyIDHex {
		t.Fatalf("kid mismatch")
	}
}

func TestV2AADMismatchFails(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	aadBytes, _ := CanonicalAAD(aad)
	blob, err := Encrypt(k.Bytes, []byte("hi"), aadBytes, k.KeyIDHex)
	if err != nil {
		t.Fatal(err)
	}
	wrong := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeProfile, ID: "profile", ClerkUserID: "u"}
	wrongBytes, _ := CanonicalAAD(wrong)
	_, err = DecryptV2(blob, []Key{k}, func(string) ([]byte, error) { return wrongBytes, nil })
	if err == nil {
		t.Fatalf("expected AAD mismatch decrypt failure")
	}
}

func TestV2NoMatchingKey(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	aadBytes, _ := CanonicalAAD(aad)
	blob, err := Encrypt(k.Bytes, []byte("hi"), aadBytes, k.KeyIDHex)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptV2(blob, []Key{other}, func(string) ([]byte, error) { return aadBytes, nil })
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("expected ErrNoMatchingKey, got %v", err)
	}
}

func TestDetectAllFormats(t *testing.T) {
	v0 := []byte(`{"iv":"AAECAwQFBgcICQoL","data":"AAAAAAAA"}`)
	if Detect(v0) != VersionV0 {
		t.Fatalf("v0 detect failed")
	}

	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	zw.Write(bytes.Repeat([]byte{0}, cryptopkg.NonceSize+cryptopkg.TagSize))
	zw.Close()
	if Detect(gzbuf.Bytes()) != VersionV1 {
		t.Fatalf("v1 detect failed")
	}

	v2 := []byte(`{"v":2,"kid":"` + strings.Repeat("a", 32) + `","alg":"AES-256-GCM","iv":"` + strings.Repeat("0", 24) + `","ct":""}`)
	if Detect(v2) != VersionV2 {
		t.Fatalf("v2 detect failed")
	}

	if Detect([]byte("garbage")) != VersionUnknown {
		t.Fatalf("garbage should be unknown")
	}
	if Detect(nil) != VersionUnknown {
		t.Fatalf("nil should be unknown")
	}
}

func TestDecryptLegacyV0RoundTrip(t *testing.T) {
	k := newKey(t)
	pt := []byte("legacy v0 plaintext")
	nonce, ct, err := cryptopkg.Seal(k.Bytes, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	v0 := legacyV0{
		IV:   base64.StdEncoding.EncodeToString(nonce),
		Data: base64.StdEncoding.EncodeToString(ct),
	}
	raw, _ := json.Marshal(v0)
	res, err := DecryptLegacy(raw, []Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, pt) {
		t.Fatalf("plaintext mismatch")
	}
	if !res.NeedsRewrap {
		t.Fatalf("v0 must signal needs_rewrap")
	}
	if res.Version != VersionV0 {
		t.Fatalf("wrong version: %v", res.Version)
	}
}

func TestDecryptLegacyV0HexIV(t *testing.T) {
	k := newKey(t)
	pt := []byte("legacy v0 hex iv")
	nonce, ct, err := cryptopkg.Seal(k.Bytes, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	v0 := legacyV0{
		IV:   hex.EncodeToString(nonce),
		Data: base64.StdEncoding.EncodeToString(ct),
	}
	raw, _ := json.Marshal(v0)
	res, err := DecryptLegacy(raw, []Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, pt) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDecryptLegacyV1RoundTrip(t *testing.T) {
	k := newKey(t)
	pt := []byte("legacy v1 plaintext")
	nonce, ct, err := cryptopkg.Seal(k.Bytes, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	framed := append(nonce, ct...)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(framed)
	zw.Close()
	res, err := DecryptLegacy(buf.Bytes(), []Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, pt) {
		t.Fatalf("plaintext mismatch")
	}
	if res.Version != VersionV1 {
		t.Fatalf("wrong version: %v", res.Version)
	}
	if !res.NeedsRewrap {
		t.Fatalf("v1 must signal needs_rewrap")
	}
}

func TestDecryptLegacyTriesAllKeys(t *testing.T) {
	wrong := newKey(t)
	right := newKey(t)
	pt := []byte("multi-key try")
	nonce, ct, err := cryptopkg.Seal(right.Bytes, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	v0 := legacyV0{
		IV:   base64.StdEncoding.EncodeToString(nonce),
		Data: base64.StdEncoding.EncodeToString(ct),
	}
	raw, _ := json.Marshal(v0)
	res, err := DecryptLegacy(raw, []Key{wrong, right})
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyIDHex != right.KeyIDHex {
		t.Fatalf("expected to land on right.KeyIDHex")
	}
}

func TestDecryptLegacyFailsWhenNoKeyWorks(t *testing.T) {
	owner := newKey(t)
	other := newKey(t)
	pt := []byte("x")
	nonce, ct, err := cryptopkg.Seal(owner.Bytes, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	v0 := legacyV0{
		IV:   base64.StdEncoding.EncodeToString(nonce),
		Data: base64.StdEncoding.EncodeToString(ct),
	}
	raw, _ := json.Marshal(v0)
	if _, err := DecryptLegacy(raw, []Key{other}); !errors.Is(err, ErrLegacyDecrypt) {
		t.Fatalf("expected ErrLegacyDecrypt, got %v", err)
	}
}

func TestEncryptRejectsBadInputs(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x"), nil, strings.Repeat("a", 32)); err == nil {
		t.Fatalf("expected key size error")
	}
	if _, err := Encrypt(make([]byte, cryptopkg.KeySize), []byte("x"), nil, "short"); err == nil {
		t.Fatalf("expected kid error")
	}
}
