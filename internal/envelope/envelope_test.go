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

func keyFromHex(t *testing.T, rawHex string) Key {
	t.Helper()
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatal(err)
	}
	id, err := cryptopkg.DeriveKeyID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Bytes: raw, KeyIDHex: cryptopkg.KeyIDHex(id)}
}

func TestCanonicalPayloadAADStable(t *testing.T) {
	a := AAD{
		KeyIDHex:    strings.Repeat("ab", 16),
		Scope:       ScopeChat,
		ID:          "chat_abc",
		ClerkUserID: "user_xyz",
	}
	b1, err := CanonicalPayloadAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := CanonicalPayloadAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("not stable: %s vs %s", b1, b2)
	}
	// The payload AAD deliberately omits the CEK key id so the payload
	// ciphertext survives a CEK rotation unchanged.
	want := `{"alg":"AES-256-GCM","clerk_user_id":"user_xyz","domain":"tinfoil-sync-envelope-v2","id":"chat_abc","scope":"chat","v":2}`
	if string(b1) != want {
		t.Fatalf("canonical payload AAD mismatch:\n got:  %s\n want: %s", b1, want)
	}
}

func TestCanonicalDEKWrapAADStable(t *testing.T) {
	a := AAD{
		KeyIDHex:    strings.Repeat("ab", 16),
		Scope:       ScopeChat,
		ID:          "chat_abc",
		ClerkUserID: "user_xyz",
	}
	out, err := CanonicalDEKWrapAAD(a)
	if err != nil {
		t.Fatal(err)
	}
	// The wrap AAD binds the CEK key id (the only field a rotation
	// rewrites) plus the owning user, row, and scope.
	want := `{"clerk_user_id":"user_xyz","domain":"tinfoil-dek-wrap-v2","id":"chat_abc","kid":"abababababababababababababababab","scope":"chat","v":2}`
	if string(out) != want {
		t.Fatalf("canonical wrap AAD mismatch:\n got:  %s\n want: %s", out, want)
	}
}

func TestCanonicalPayloadAADRejectsInvalid(t *testing.T) {
	cases := []AAD{
		{Scope: "chat", ID: "x", ClerkUserID: ""},
		{Scope: "chat", ID: "", ClerkUserID: "u"},
		{Scope: "profile", ID: "", ClerkUserID: "u"},
		{Scope: "project", ID: "", ClerkUserID: "u"},
		{Scope: "project_document", ID: "", ClerkUserID: "u"},
		{Scope: "bogus", ID: "x", ClerkUserID: "u"},
	}
	for i, c := range cases {
		if _, err := CanonicalPayloadAAD(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestCanonicalDEKWrapAADRejectsInvalid(t *testing.T) {
	cases := []AAD{
		{Scope: "chat", KeyIDHex: "tooShort", ID: "x", ClerkUserID: "u"},
		{Scope: "chat", KeyIDHex: strings.Repeat("A", 32), ID: "x", ClerkUserID: "u"},
		{Scope: "chat", KeyIDHex: strings.Repeat("a", 32), ID: "x", ClerkUserID: ""},
		{Scope: "chat", KeyIDHex: strings.Repeat("a", 32), ID: "", ClerkUserID: "u"},
		{Scope: "profile", KeyIDHex: strings.Repeat("a", 32), ID: "", ClerkUserID: "u"},
		{Scope: "bogus", KeyIDHex: strings.Repeat("a", 32), ID: "x", ClerkUserID: "u"},
	}
	for i, c := range cases {
		if _, err := CanonicalDEKWrapAAD(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestCanonicalPayloadAADRequiresExplicitProfileID(t *testing.T) {
	a := AAD{
		KeyIDHex:    strings.Repeat("c", 32),
		Scope:       ScopeProfile,
		ID:          ProfileSingletonID,
		ClerkUserID: "u",
	}
	out, err := CanonicalPayloadAAD(a)
	if err != nil {
		t.Fatalf("explicit profile id should succeed: %v", err)
	}
	if !strings.Contains(string(out), `"id":"profile"`) {
		t.Fatalf("profile ID not present: %s", out)
	}

	missing := AAD{
		KeyIDHex:    strings.Repeat("c", 32),
		Scope:       ScopeProfile,
		ClerkUserID: "u",
	}
	if _, err := CanonicalPayloadAAD(missing); err == nil {
		t.Fatal("profile AAD without explicit id must fail")
	}

	wrong := AAD{
		KeyIDHex:    strings.Repeat("c", 32),
		Scope:       ScopeProfile,
		ID:          "typo",
		ClerkUserID: "u",
	}
	if _, err := CanonicalPayloadAAD(wrong); err == nil {
		t.Fatal("profile AAD with non-canonical id must fail")
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

func TestV2RoundTrip(t *testing.T) {
	k := newKey(t)
	aad := AAD{
		KeyIDHex:    k.KeyIDHex,
		Scope:       ScopeChat,
		ID:          "chat_1",
		ClerkUserID: "user_a",
	}
	pt := []byte("the quick brown fox")
	blob, err := Encrypt(k.Bytes, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if Detect(blob) != VersionV2 {
		t.Fatalf("detect: %v", Detect(blob))
	}
	res, err := DecryptV2(blob, []Key{k}, aad)
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

// TestV2EnvelopeIsGzippedBeforeEncrypt asserts that the v2 pipeline is
// gzip-then-encrypt: AES-GCM-Open of the envelope ciphertext yields gzipped
// bytes (gzip magic 0x1f 0x8b at offset 0), not the raw plaintext.
// Compressing before encrypting is required because ciphertext is random and
// cannot be compressed at any downstream layer.
func TestV2EnvelopeIsGzippedBeforeEncrypt(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	plaintext := bytes.Repeat([]byte("compress-me-"), 256)
	blob, err := Encrypt(k.Bytes, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	var env V2
	if err := json.Unmarshal(blob, &env); err != nil {
		t.Fatal(err)
	}
	// The payload is sealed under a per-message data key, not the CEK, so
	// unwrap the data key first (CEK + wrap AAD), then open the payload
	// (data key + payload AAD) and assert the gzip header is inside.
	wrapAAD, err := CanonicalDEKWrapAAD(aad)
	if err != nil {
		t.Fatal(err)
	}
	wrapIV, err := hex.DecodeString(env.WIV)
	if err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(env.WDEK)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := cryptopkg.Open(k.Bytes, wrapIV, wrappedDEK, wrapAAD)
	if err != nil {
		t.Fatal(err)
	}
	payloadAAD, err := CanonicalPayloadAAD(aad)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hex.DecodeString(env.IV)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := cryptopkg.Open(dek, iv, ct, payloadAAD)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) < 2 || inner[0] != 0x1f || inner[1] != 0x8b {
		t.Fatalf("expected gzip header inside v2 ciphertext, got prefix %x", inner[:min(2, len(inner))])
	}
	if len(blob) >= len(plaintext) {
		t.Logf("note: compressed blob (%d) is not smaller than plaintext (%d) — fine for tiny inputs", len(blob), len(plaintext))
	}
}

func TestV2DecryptRejectsCorruptGzip(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	payloadAAD, err := CanonicalPayloadAAD(aad)
	if err != nil {
		t.Fatal(err)
	}
	wrapAAD, err := CanonicalDEKWrapAAD(aad)
	if err != nil {
		t.Fatal(err)
	}
	// Build a well-formed v2 envelope whose payload plaintext is NOT gzip.
	// The decrypt path must hard-fail rather than hand back non-gzip bytes.
	dek, err := cryptopkg.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	payloadIV, payloadCT, err := cryptopkg.Seal(dek, []byte(`{"hello":"world"}`), payloadAAD)
	if err != nil {
		t.Fatal(err)
	}
	wrapIV, wrappedDEK, err := cryptopkg.Seal(k.Bytes, dek, wrapAAD)
	if err != nil {
		t.Fatal(err)
	}
	env := V2{
		V:    int(VersionV2),
		Alg:  AlgAESGCM,
		KID:  k.KeyIDHex,
		WDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		WIV:  hex.EncodeToString(wrapIV),
		IV:   hex.EncodeToString(payloadIV),
		CT:   base64.StdEncoding.EncodeToString(payloadCT),
	}
	blob, _ := json.Marshal(env)
	_, err = DecryptV2(blob, []Key{k}, aad)
	if !errors.Is(err, ErrV2Malformed) {
		t.Fatalf("expected ErrV2Malformed for non-gzip v2 payload, got %v", err)
	}
}

func TestV2AADMismatchFails(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	blob, err := Encrypt(k.Bytes, []byte("hi"), aad)
	if err != nil {
		t.Fatal(err)
	}
	wrong := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeProfile, ID: "profile", ClerkUserID: "u"}
	_, err = DecryptV2(blob, []Key{k}, wrong)
	if err == nil {
		t.Fatalf("expected AAD mismatch decrypt failure")
	}
}

// TestV2RejectsNonCanonicalBase64CT pins the wire-level rule that
// the `ct` field must be exact-canonical base64. The check covers
// both 1-pad (`...X=`) and 2-pad (`...XX==`) trailing groups, since
// each carries a different number of spare bits (2 and 4
// respectively) and a permissive decoder treats both as a no-op.
// Without this rule a bit-flipped spare bit passes AES-GCM
// verification unchanged, which looks like an AEAD bypass to
// anyone tampering byte-by-byte even though AES-GCM has done its
// job correctly.
func TestV2RejectsNonCanonicalBase64CT(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}

	// Sweep payload sizes so we exercise every `0-, 1-, 2-pad`
	// base64 trailing group; each one needs to be caught by the
	// strict decoder, otherwise a partial fix could let the
	// remaining padding shape leak through.
	covered := map[string]bool{"=": false, "==": false}
	for size := 1; size <= 24; size++ {
		blob, err := Encrypt(k.Bytes, bytes.Repeat([]byte{0xAB}, size), aad)
		if err != nil {
			t.Fatal(err)
		}
		var env V2
		if err := json.Unmarshal(blob, &env); err != nil {
			t.Fatal(err)
		}
		pad := trailingPadding(env.CT)
		if pad == "" || covered[pad] {
			continue
		}
		nonCanonical, ok := altBase64SameDecode(env.CT)
		if !ok {
			continue
		}
		env.CT = nonCanonical
		mutated, _ := json.Marshal(env)
		_, err = DecryptV2(mutated, []Key{k}, aad)
		if !errors.Is(err, ErrV2Malformed) {
			t.Fatalf("expected ErrV2Malformed for non-canonical base64 ct (pad=%q size=%d), got %v", pad, size, err)
		}
		covered[pad] = true
		if covered["="] && covered["=="] {
			break
		}
	}
	for pad, ok := range covered {
		if !ok {
			t.Fatalf("non-canonical base64 case for pad %q was never exercised; test setup bug", pad)
		}
	}
}

// TestV2RejectsWhitespaceInBase64CT pins that an attacker who
// injects `\n` or `\r` into the `ct` field gets a malformed-error
// rather than a successful decrypt with a wire-different ct
// string. base64.StdEncoding.Strict() alone tolerates whitespace,
// so DecryptV2 also runs an explicit alphabet check.
func TestV2RejectsWhitespaceInBase64CT(t *testing.T) {
	k := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	blob, err := Encrypt(k.Bytes, []byte("hello world"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, inject := range []string{"\n", "\r", "\r\n", " ", "\t"} {
		var env V2
		if err := json.Unmarshal(blob, &env); err != nil {
			t.Fatal(err)
		}
		// Inject the whitespace in the middle of ct (after the
		// first 4-char group) so it lands inside the run of
		// alphabet chars rather than next to the padding.
		if len(env.CT) < 8 {
			t.Fatalf("ciphertext shorter than expected: %d", len(env.CT))
		}
		env.CT = env.CT[:4] + inject + env.CT[4:]
		mutated, _ := json.Marshal(env)
		_, err = DecryptV2(mutated, []Key{k}, aad)
		if !errors.Is(err, ErrV2Malformed) {
			t.Fatalf("expected ErrV2Malformed for ct containing %q, got %v", inject, err)
		}
	}
}

// trailingPadding returns the run of `=` characters at the end of s.
func trailingPadding(s string) string {
	i := len(s)
	for i > 0 && s[i-1] == '=' {
		i--
	}
	return s[i:]
}

// altBase64SameDecode returns an alternate base64 string that
// decodes to the same bytes as s but differs in the trailing
// "spare bits" of the final data character. Returns (_, false)
// when s ends in `==` whose only data char already encodes zero
// spare bits, or when s has no padding at all.
func altBase64SameDecode(s string) (string, bool) {
	if !strings.HasSuffix(s, "=") {
		return "", false
	}
	// Strip the `=` chars, look at the last data char, and
	// derive an alternate by adding 1 to its base64 value (mod 64).
	// We then re-decode and re-encode the result via the stdlib
	// canonicalizer to confirm the alternate is non-canonical.
	stripped := strings.TrimRight(s, "=")
	if len(stripped) == 0 {
		return "", false
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lastIdx := len(stripped) - 1
	v := strings.IndexByte(alphabet, stripped[lastIdx])
	if v < 0 {
		return "", false
	}
	// Try every neighbor in base64-value space; one of them will
	// share the same canonical decoding.
	originalRaw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}
	for delta := 1; delta < 64; delta++ {
		candidateVal := (v + delta) % 64
		if candidateVal == v {
			continue
		}
		candidate := stripped[:lastIdx] + string(alphabet[candidateVal]) + s[len(stripped):]
		raw, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			continue
		}
		if bytes.Equal(raw, originalRaw) && candidate != s {
			return candidate, true
		}
	}
	return "", false
}

func TestV2NoMatchingKey(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	aad := AAD{KeyIDHex: k.KeyIDHex, Scope: ScopeChat, ID: "c", ClerkUserID: "u"}
	blob, err := Encrypt(k.Bytes, []byte("hi"), aad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptV2(blob, []Key{other}, aad)
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("expected ErrNoMatchingKey, got %v", err)
	}
}

func TestDetectAllFormats(t *testing.T) {
	v0 := []byte(`{"iv":"AAECAwQFBgcICQoL","data":"AAAAAAAA"}`)
	if Detect(v0) != VersionV0 {
		t.Fatalf("v0 detect failed")
	}

	// Production v1 wire format: random IV byte at offset 0 followed by
	// AES-GCM ciphertext of gzipped JSON. Anything that is not JSON and
	// is at least IV+TAG bytes long must register as v1.
	v1 := make([]byte, cryptopkg.NonceSize+cryptopkg.TagSize+8)
	for i := range v1 {
		v1[i] = byte(i + 1)
	}
	if Detect(v1) != VersionV1 {
		t.Fatalf("v1 detect (raw binary) failed")
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

// TestDetect_V1WithJSONPrefixNonce pins the guarantee that a v1
// binary blob whose nonce starts with `{` or `{"` — the byte
// patterns that look like the opening of a JSON envelope — still
// classifies as v1. The discriminator must rely on a successful
// JSON parse, not a prefix check; under prefix-only rules a real
// production v1 blob with this nonce would silently route to the
// JSON branch and become permanently undecryptable.
func TestDetect_V1WithJSONPrefixNonce(t *testing.T) {
	// Construct a blob shaped exactly like v1: nonce(12) || ct+tag.
	// Pin the first two nonce bytes to `{` and `"` to exercise the
	// adversarial case; the remaining bytes are any value that
	// doesn't accidentally parse as JSON.
	blob := make([]byte, cryptopkg.NonceSize+cryptopkg.TagSize+8)
	for i := range blob {
		blob[i] = byte(i + 1)
	}
	blob[0] = '{'
	blob[1] = '"'
	if Detect(blob) != VersionV1 {
		t.Fatalf("v1 blob with JSON-prefix nonce must classify as v1, not %v", Detect(blob))
	}
}

// TestDetect_TruncatedV2FallsThroughToV1 pins the trade-off baked
// into the strict-parse cascade: a truncated v2 envelope fails the
// full JSON parse and is treated as v1. DecryptLegacy then fails to
// decrypt the malformed bytes and surfaces a decrypt error to the
// caller. This is unavoidable from the wire format — v1 has no
// version tag, so anything that does not parse as a complete v0 /
// v2 envelope must be tried as v1 first to keep real v1 blobs
// decryptable. The pin exists to make this trade-off explicit in
// the test suite so any future "tighten Detect to return Unknown
// on parse failure" change has to deal with the contract loudly.
func TestDetect_TruncatedV2FallsThroughToV1(t *testing.T) {
	truncated := []byte(`{"v":2,"kid":"aaaa`)
	// Long enough to look like a v1 blob byte-count wise; the test
	// asserts the dispatch decision, not the decrypt outcome.
	pad := make([]byte, cryptopkg.NonceSize+cryptopkg.TagSize)
	truncated = append(truncated, pad...)
	if got := Detect(truncated); got != VersionV1 {
		t.Fatalf("truncated v2 must fall through to v1 (so DecryptLegacy is tried), got %v", got)
	}
}

// TestDetect_V0RequiresIvAndDataFields locks in the shape contract
// for v0: a JSON object missing one of the required legacy fields
// is not v0 even when the prefix looks JSON-ish.
func TestDetect_V0RequiresIvAndDataFields(t *testing.T) {
	missingData := []byte(`{"iv":"aaaaaaaaaaaa"}`)
	if got := Detect(missingData); got == VersionV0 {
		t.Fatalf("v0 detection must require both iv and data, got %v", got)
	}
	missingIv := []byte(`{"data":"aaaaaaaa"}`)
	if got := Detect(missingIv); got == VersionV0 {
		t.Fatalf("v0 detection must require both iv and data, got %v", got)
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

// TestDecryptLegacyV1RoundTrip exercises the legacy v1 wire format:
// IV(12) || AES-GCM-ciphertext(gzip(JSON)).
func TestDecryptLegacyV1RoundTrip(t *testing.T) {
	k := newKey(t)
	payload := map[string]any{
		"title":     "legacy v1 chat",
		"createdAt": "2024-04-01T12:34:56.000Z",
		"messages":  []any{"hello", "world"},
	}
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	if _, err := zw.Write(jsonBytes); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := cryptopkg.Seal(k.Bytes, gzbuf.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(nonce, ct...)
	if Detect(blob) != VersionV1 {
		t.Fatalf("Detect should classify IV||AES-GCM(gzip(JSON)) as v1")
	}
	res, err := DecryptLegacy(blob, []Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, jsonBytes) {
		t.Fatalf("plaintext mismatch: got %s want %s", res.Plaintext, jsonBytes)
	}
	if res.Version != VersionV1 {
		t.Fatalf("wrong version: %v", res.Version)
	}
	if !res.NeedsRewrap {
		t.Fatalf("v1 must signal needs_rewrap")
	}
}

// TestRewrapV1WebappFixture round-trips a fixed v1 blob produced by
// the webapp's pako + WebCrypto `compressAndEncrypt` pipeline through
// the decrypt → re-encrypt(v2) path that the migrate handler runs.
func TestRewrapV1WebappFixture(t *testing.T) {
	oldKey := keyFromHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	newKey := newKey(t)
	chatID := "chat_prod_v1_blob"
	clerkUserID := "user_prod_v1"

	jsonBytes := []byte(`{"title":"prod v1 round trip","messages":["hello","world"],"isDeleted":false,"updatedAt":"2024-05-15T10:00:00.000Z"}`)
	v1Blob, err := hex.DecodeString("202122232425262728292a2bcdb1ae706c981a0e1a7f57427012f6c8c04c93b93bba4475af9dbe1b3708cb8e30eeb209220351a94e7591fcdc6079421b8a0b2018b4f76b75350fb020fd7c603d2c428c0e327e8e69e0528f2d8ce7c4fc74d1955ad3ac43d7be58fede7f3540844bd4ae057071d4933a149ba1b337a05333bcfcae5eedd93286070ff5f38b21938d3fc8bed6402c8c5deea465")
	if err != nil {
		t.Fatal(err)
	}

	res, err := DecryptLegacy(v1Blob, []Key{oldKey})
	if err != nil {
		t.Fatalf("decrypt legacy v1: %v", err)
	}
	if !res.NeedsRewrap {
		t.Fatalf("legacy v1 must signal needs_rewrap")
	}

	aad := AAD{
		KeyIDHex:    newKey.KeyIDHex,
		Scope:       ScopeChat,
		ID:          chatID,
		ClerkUserID: clerkUserID,
	}
	v2Blob, err := Encrypt(newKey.Bytes, res.Plaintext, aad)
	if err != nil {
		t.Fatalf("rewrap encrypt: %v", err)
	}
	if Detect(v2Blob) != VersionV2 {
		t.Fatalf("rewrap output should be v2")
	}

	got, err := DecryptV2(v2Blob, []Key{newKey}, AAD{
		Scope:       ScopeChat,
		ID:          chatID,
		ClerkUserID: clerkUserID,
	})
	if err != nil {
		t.Fatalf("decrypt v2: %v", err)
	}
	if !bytes.Equal(got.Plaintext, jsonBytes) {
		t.Fatalf("rewrap plaintext mismatch")
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
	valid := AAD{KeyIDHex: strings.Repeat("a", 32), Scope: ScopeChat, ID: "x", ClerkUserID: "u"}
	if _, err := Encrypt(make([]byte, 16), []byte("x"), valid); err == nil {
		t.Fatalf("expected key size error")
	}
	badKID := AAD{KeyIDHex: "short", Scope: ScopeChat, ID: "x", ClerkUserID: "u"}
	if _, err := Encrypt(make([]byte, cryptopkg.KeySize), []byte("x"), badKID); err == nil {
		t.Fatalf("expected kid error")
	}
}
