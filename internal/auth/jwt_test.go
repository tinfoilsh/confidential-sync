package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type testIssuer struct {
	server   *httptest.Server
	issuer   string
	signKey  *rsa.PrivateKey
	signKID  string
	jwksURL  string
	jwksJSON []byte
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key-1"

	jwk := buildJWK(t, priv, kid)
	jwksJSON, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	ti := &testIssuer{
		server:   srv,
		issuer:   srv.URL,
		signKey:  priv,
		signKID:  kid,
		jwksURL:  srv.URL + "/.well-known/jwks.json",
		jwksJSON: jwksJSON,
	}
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(ti.jwksJSON)
	})
	t.Cleanup(srv.Close)
	return ti
}

func buildJWK(t *testing.T, priv *rsa.PrivateKey, kid string) map[string]any {
	t.Helper()
	pub := priv.Public().(*rsa.PublicKey)
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64URLUInt(pub.N),
		"e":   base64URLUInt(big.NewInt(int64(pub.E))),
	}
}

func base64URLUInt(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

func (ti *testIssuer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = ti.signKID
	s, err := tok.SignedString(ti.signKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (ti *testIssuer) verifier(t *testing.T) Verifier {
	t.Helper()
	ctx := context.Background()
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{ti.jwksURL})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifierWithKeyfunc(Config{Issuer: ti.issuer}, kf)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func validClaims(iss string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub": "user_abc",
		"iss": iss,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

func TestVerifierAcceptsValidToken(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	tok := ti.sign(t, validClaims(ti.issuer))
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user_abc" {
		t.Fatalf("sub mismatch: %q", claims.Subject)
	}
	if claims.Issuer != ti.issuer {
		t.Fatalf("iss mismatch: %q", claims.Issuer)
	}
}

func TestVerifierRejectsExpiredToken(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	c := validClaims(ti.issuer)
	c["exp"] = time.Now().Add(-time.Minute).Unix()
	tok := ti.sign(t, c)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerifierRejectsWrongIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	c := validClaims("https://attacker.example.com")
	tok := ti.sign(t, c)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected verification failure, got %v", err)
	}
}

func TestVerifierRejectsTamperedSignature(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	tok := ti.sign(t, validClaims(ti.issuer))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token")
	}
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAA"
	if _, err := v.Verify(context.Background(), tampered); err == nil {
		t.Fatalf("expected error")
	}
}

func TestVerifierRejectsUnknownKID(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	c := validClaims(ti.issuer)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "does-not-exist"
	s, err := tok.SignedString(ti.signKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), s); err == nil {
		t.Fatalf("expected error for unknown kid")
	}
}

func TestVerifierEnforcesAudienceWhenConfigured(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{ti.jwksURL})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifierWithKeyfunc(Config{
		Issuer:   ti.issuer,
		Audience: "tinfoil-sync",
	}, kf)
	if err != nil {
		t.Fatal(err)
	}

	c := validClaims(ti.issuer)
	c["aud"] = "tinfoil-sync"
	if _, err := v.Verify(ctx, ti.sign(t, c)); err != nil {
		t.Fatalf("expected audience match, got %v", err)
	}

	c["aud"] = "wrong"
	if _, err := v.Verify(ctx, ti.sign(t, c)); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifierRequiresSubject(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	c := validClaims(ti.issuer)
	delete(c, "sub")
	if _, err := v.Verify(context.Background(), ti.sign(t, c)); !errors.Is(err, ErrSubjectMissing) {
		t.Fatalf("expected ErrSubjectMissing, got %v", err)
	}
}

func TestVerifierRejectsHS256(t *testing.T) {
	ti := newTestIssuer(t)
	v := ti.verifier(t)
	c := validClaims(ti.issuer)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tok.Header["kid"] = ti.signKID
	s, err := tok.SignedString([]byte("hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), s); err == nil {
		t.Fatalf("expected rejection of HS256 token")
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := map[string]bool{
		"Bearer abc":      true,
		"Bearer  abc":     true,
		"Bearer ":         false,
		"":                false,
		"Token abc":       false,
		"bearer abc":      false,
		"Bearer abc def":  true,
	}
	for h, want := range cases {
		tok, err := BearerToken(h)
		gotOK := err == nil && tok != ""
		if gotOK != want {
			t.Fatalf("BearerToken(%q): ok=%v, want %v (err=%v, tok=%q)", h, gotOK, want, err, tok)
		}
	}
}
