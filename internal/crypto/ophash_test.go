package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Per syncplan.md §7.0, both the enclave and the web client carry the
// following test vector to guarantee canonical encoding + HMAC inputs
// match byte-for-byte. The expected hash is computed once and pinned.

const (
	vectorCEKHex      = "4242424242424242424242424242424242424242424242424242424242424242"
	vectorMethod      = "PUT"
	vectorPath        = "/api/profile/"
	vectorKeyIDHex    = "00112233445566778899aabbccddeeff"
	vectorIfMatch     = "0"
	vectorIdemKey     = "0123456789abcdef"
	vectorBody        = `{"data":"hello"}`
	pinnedExpectedHex = "518d0af258a1001dbf5689ac11f85d783d152adcf664a24ef996010b12b52e23"
)

func TestDeriveOpHashKey_LengthsAndDeterminism(t *testing.T) {
	cek := bytes.Repeat([]byte{0x42}, KeySize)
	got, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("subkey length = %d, want 32", len(got))
	}
	got2, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(got, got2) {
		t.Fatal("HKDF is not deterministic for the same IKM")
	}
}

func TestDeriveOpHashKey_DomainSeparation(t *testing.T) {
	cek := bytes.Repeat([]byte{0x42}, KeySize)
	op, _ := DeriveOpHashKey(cek)
	kid, _ := DeriveKeyID(cek)
	if bytes.Equal(op[:KeyIDSize], kid[:]) {
		t.Fatal("op-hash subkey aliases key-id derivation; domain separation broken")
	}
}

func TestDeriveOpHashKey_RejectsBadIKM(t *testing.T) {
	if _, err := DeriveOpHashKey([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short CEK")
	}
}

func TestCanonical_LengthPrefixing(t *testing.T) {
	in := CanonicalInput{
		Method: "AB", Path: "C", KeyIDHex: "", IfMatch: "0",
		IdempotencyKey: "I", Body: []byte("D"),
		AAD: []byte("E"), Envelope: []byte("FG"),
	}
	got := AppendCanonical(nil, in)
	want := []byte{
		0, 0, 0, 2, 'A', 'B',
		0, 0, 0, 1, 'C',
		0, 0, 0, 0,
		0, 0, 0, 1, '0',
		0, 0, 0, 1, 'I',
		0, 0, 0, 1, 'D',
		0, 0, 0, 1, 'E',
		0, 0, 0, 2, 'F', 'G',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestCanonical_BodyOnlyOpsStable pins the body-only encoding so a
// RegisterKey/AddBundle retry under the same idempotency key continues
// to MAC to the exact same bytes after AAD/Envelope were added for
// blob ops.
func TestCanonical_BodyOnlyOpsStable(t *testing.T) {
	in := CanonicalInput{
		Method: "POST", Path: "/p", KeyIDHex: "",
		IfMatch: "", IdempotencyKey: "i", Body: []byte("body"),
	}
	got := AppendCanonical(nil, in)
	want := []byte{
		0, 0, 0, 4, 'P', 'O', 'S', 'T',
		0, 0, 0, 2, '/', 'p',
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 1, 'i',
		0, 0, 0, 4, 'b', 'o', 'd', 'y',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body-only canonical drift:\n got  %x\n want %x", got, want)
	}
}

func TestCanonical_ExtendedEncodingUsesFieldPresence(t *testing.T) {
	base := CanonicalInput{
		Method: "PUT", Path: "/p", KeyIDHex: "kid",
		IfMatch: "0", IdempotencyKey: "i", Body: []byte("body"),
	}
	legacy := AppendCanonical(nil, base)
	withEmpty := base
	withEmpty.AAD = []byte{}
	withEmpty.Envelope = []byte{}
	got := AppendCanonical(nil, withEmpty)
	want := append([]byte{}, legacy...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("empty present AAD/envelope must use extended encoding:\n got  %x\n want %x", got, want)
	}
}

// TestVector_Section7_0 pins the test vector from syncplan.md §7.0.
// If this test fails, either:
//
//	(a) the canonical encoding drifted, or
//	(b) the HKDF/HMAC parameters drifted.
//
// Either way the web client will start rejecting our writes (or vice
// versa) at runtime. Treat a failure as a protocol break.
func TestVector_Section7_0(t *testing.T) {
	cek := mustHex(t, vectorCEKHex)
	opKey, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got := ComputeOperationHash(opKey, CanonicalInput{
		Method:         vectorMethod,
		Path:           vectorPath,
		KeyIDHex:       vectorKeyIDHex,
		IfMatch:        vectorIfMatch,
		IdempotencyKey: vectorIdemKey,
		Body:           []byte(vectorBody),
	})
	if !strings.EqualFold(got, pinnedExpectedHex) {
		t.Fatalf("op-hash drift detected\n  got  %s\n  want %s", got, pinnedExpectedHex)
	}
}

func TestVerifyOperationHash(t *testing.T) {
	cek := mustHex(t, vectorCEKHex)
	in := CanonicalInput{
		Method:         vectorMethod,
		Path:           vectorPath,
		KeyIDHex:       vectorKeyIDHex,
		IfMatch:        vectorIfMatch,
		IdempotencyKey: vectorIdemKey,
		Body:           []byte(vectorBody),
	}

	ok, err := VerifyOperationHash(cek, pinnedExpectedHex, in)
	if err != nil || !ok {
		t.Fatalf("Verify(legit) ok=%v err=%v", ok, err)
	}

	// Any single-bit perturbation of the body must invalidate the MAC.
	bad := in
	bad.Body = []byte(vectorBody + "!")
	ok, err = VerifyOperationHash(cek, pinnedExpectedHex, bad)
	if err != nil {
		t.Fatalf("Verify(perturbed): err=%v", err)
	}
	if ok {
		t.Fatal("Verify accepted a perturbed body")
	}

	// Non-hex / wrong length → rejected as invalid, not erroring.
	ok, err = VerifyOperationHash(cek, "not-hex", in)
	if err != nil {
		t.Fatalf("Verify(non-hex): unexpected err %v", err)
	}
	if ok {
		t.Fatal("Verify accepted non-hex hash")
	}
}

func TestOpHashChangesWhenEnvelopeChanges(t *testing.T) {
	cek := mustHex(t, vectorCEKHex)
	opKey, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatal(err)
	}
	base := CanonicalInput{
		Method:         "PUT",
		Path:           "/api/sync/blob/chat/c1",
		KeyIDHex:       "00112233445566778899aabbccddeeff",
		IfMatch:        "0",
		IdempotencyKey: "i1",
		AAD:            []byte("aad-bytes"),
		Envelope:       []byte("envelope-bytes-A"),
	}
	a := ComputeOperationHash(opKey, base)
	b := base
	b.Envelope = []byte("envelope-bytes-B")
	if got := ComputeOperationHash(opKey, b); got == a {
		t.Fatal("op-hash did not change when envelope bytes differed")
	}
}

func TestOpHashChangesWhenAADChanges(t *testing.T) {
	cek := mustHex(t, vectorCEKHex)
	opKey, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatal(err)
	}
	base := CanonicalInput{
		Method:         "PUT",
		Path:           "/api/sync/blob/chat/c1",
		KeyIDHex:       "00112233445566778899aabbccddeeff",
		IfMatch:        "0",
		IdempotencyKey: "i1",
		AAD:            []byte("aad-for-chat-c1"),
		Envelope:       []byte("envelope-bytes"),
	}
	a := ComputeOperationHash(opKey, base)
	b := base
	b.AAD = []byte("aad-for-chat-c2")
	if got := ComputeOperationHash(opKey, b); got == a {
		t.Fatal("op-hash did not change when AAD differed")
	}
}

func TestOpHashStableForByteIdenticalRetry(t *testing.T) {
	cek := mustHex(t, vectorCEKHex)
	opKey, err := DeriveOpHashKey(cek)
	if err != nil {
		t.Fatal(err)
	}
	in := CanonicalInput{
		Method:         "PUT",
		Path:           "/api/sync/blob/chat/c1",
		KeyIDHex:       "00112233445566778899aabbccddeeff",
		IfMatch:        "0",
		IdempotencyKey: "i1",
		AAD:            []byte("aad"),
		Envelope:       []byte("envelope"),
	}
	if ComputeOperationHash(opKey, in) != ComputeOperationHash(opKey, in) {
		t.Fatal("op-hash is not deterministic for identical inputs")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
