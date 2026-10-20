//go:build smoke

package smoke

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// T09: every authenticated endpoint MUST reject a request with no
// Authorization header. Trivial regression: someone strips the
// authMiddleware wrapper from a route definition.
func TestT09_AuthMissingBearerRejected(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// Bypass the fixture's auth-injecting `post` helper by passing
	// an empty JWT override.
	status, _ := f.post("/v1/sync/list-status", map[string]any{"scope": "chat"}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing bearer, got %d", status)
	}
}

// T10: every authenticated endpoint MUST reject an expired JWT.
// Regression: someone removes the exp claim check.
func TestT10_AuthExpiredJWTRejected(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	expired, err := f.stack.MintJWT("user_smoke", -time.Hour) // exp 1h ago
	if err != nil {
		t.Fatalf("mint expired jwt: %v", err)
	}
	status, _ := f.post("/v1/sync/list-status", map[string]any{"scope": "chat"}, expired)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", status)
	}
}

// T11: alg-confusion attack — sign a JWT with HS256 using the
// RSA public key bytes as the HMAC secret. A naive verifier that
// blindly trusts the token's `alg` header would accept this token
// because HMAC-SHA256(public_key, payload) is computable by anyone
// who can read the JWKS.
//
// This test proves the running server rejects that forged token end
// to end. It does not pin the signing-method allowlist in auth/jwt.go
// (jwt.WithValidMethods): with HS256 allowed, the forgery still fails
// because the key lookup can only yield the RSA public key, which
// golang-jwt refuses to use as an HMAC secret. TestVerifierRejectsHMAC
// in internal/auth pins the allowlist.
//
// Reference:
// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func TestT11_AuthAlgConfusionRejected(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// Serialise the public key bytes as the attacker would (after
	// downloading the JWKS). For an RSA key, the public modulus
	// + exponent — packed as DER — is a reasonable approximation
	// of "the public material an attacker has access to."
	pubDER, err := x509.MarshalPKIXPublicKey(f.stack.SigningKey.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "user_attacker",
		"iss": f.stack.Issuer,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	// Sign with HS256 using the public key as the secret — the
	// classic alg-confusion forgery.
	forged, err := f.stack.MintJWTRaw(jwt.SigningMethodHS256, claims, f.stack.SigningKID, pubDER)
	if err != nil {
		t.Fatalf("forge hs256 token: %v", err)
	}

	status, _ := f.post("/v1/sync/list-status", map[string]any{"scope": "chat"}, forged)
	if status != http.StatusUnauthorized {
		t.Fatalf("ALG-CONFUSION: HS256-signed token accepted, expected 401 got %d", status)
	}
}
