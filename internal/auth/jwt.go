package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// Verifier validates a Clerk-issued JWT and returns the user's subject.
//
// Clerk issues JWTs signed with RS256 (asymmetric); the public keys are
// published at <issuer>/.well-known/jwks.json. The verifier:
//   - fetches the JWKS lazily and caches it
//   - selects the signing key by the JWT header's `kid`
//   - refreshes on cache miss to handle rotation
//   - validates `iss`, `exp`, `nbf`, and (when configured) `aud`
//   - returns the `sub` claim for use in AAD and authorization
type Verifier interface {
	Verify(ctx context.Context, rawJWT string) (Claims, error)
}

type Claims struct {
	Subject   string
	Issuer    string
	Audiences []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
}

type Config struct {
	Issuer string
	// Audience is enforced if non-empty. Clerk JWTs typically omit the
	// `aud` claim by default, so we accept an empty audience configuration
	// to mean "do not enforce."
	Audience string
	// JWKSRefreshInterval is the background refresh interval. Defaults to
	// 1 hour. The verifier additionally triggers an on-demand refresh
	// when a JWT references an unknown `kid`.
	JWKSRefreshInterval time.Duration
	// Clock is injectable for tests; defaults to time.Now.
	Clock func() time.Time
	// HTTPClient overrides the JWKS HTTP client; defaults to a 10-second
	// timeout client. Useful in tests.
	HTTPClient *http.Client
}

type clerkVerifier struct {
	issuer   string
	audience string
	kf       keyfunc.Keyfunc
	clock    func() time.Time
}

var (
	ErrMissingIssuer    = errors.New("auth: issuer is required")
	ErrTokenMissing     = errors.New("auth: missing bearer token")
	ErrTokenInvalid     = errors.New("auth: token invalid")
	ErrSubjectMissing   = errors.New("auth: token has no subject")
	ErrIssuerMismatch   = errors.New("auth: issuer mismatch")
	ErrAudienceMismatch = errors.New("auth: audience mismatch")
)

func NewVerifier(ctx context.Context, cfg Config) (Verifier, error) {
	if cfg.Issuer == "" {
		return nil, ErrMissingIssuer
	}
	if cfg.JWKSRefreshInterval == 0 {
		cfg.JWKSRefreshInterval = time.Hour
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	jwksURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/jwks.json"
	storage, err := jwkset.NewStorageFromHTTP(jwksURL, jwkset.HTTPClientStorageOptions{
		Client:          httpClient,
		Ctx:             ctx,
		HTTPTimeout:     10 * time.Second,
		RefreshInterval: cfg.JWKSRefreshInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: jwks storage init: %w", err)
	}

	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{jwksURL: storage},
		RefreshUnknownKID: rate.NewLimiter(rate.Every(5*time.Minute), 1),
	})
	if err != nil {
		return nil, fmt.Errorf("auth: jwks client init: %w", err)
	}
	kf, err := keyfunc.New(keyfunc.Options{
		Ctx:     ctx,
		Storage: client,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: keyfunc init: %w", err)
	}
	return &clerkVerifier{
		issuer:   strings.TrimRight(cfg.Issuer, "/"),
		audience: cfg.Audience,
		kf:       kf,
		clock:    cfg.Clock,
	}, nil
}

// NewVerifierWithKeyfunc lets callers (and tests) inject a pre-built
// keyfunc.Keyfunc so they can stand up an in-process JWKS server backed by
// real RSA keys, without going through DNS or the network.
func NewVerifierWithKeyfunc(cfg Config, kf keyfunc.Keyfunc) (Verifier, error) {
	if cfg.Issuer == "" {
		return nil, ErrMissingIssuer
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &clerkVerifier{
		issuer:   strings.TrimRight(cfg.Issuer, "/"),
		audience: cfg.Audience,
		kf:       kf,
		clock:    cfg.Clock,
	}, nil
}

func (v *clerkVerifier) Verify(ctx context.Context, rawJWT string) (Claims, error) {
	if rawJWT == "" {
		return Claims{}, ErrTokenMissing
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.clock),
	)

	parsed, err := parser.Parse(rawJWT, v.kf.Keyfunc)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if !parsed.Valid {
		return Claims{}, ErrTokenInvalid
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, ErrTokenInvalid
	}

	sub, _ := mapClaims["sub"].(string)
	if sub == "" {
		return Claims{}, ErrSubjectMissing
	}
	iss, _ := mapClaims["iss"].(string)
	if strings.TrimRight(iss, "/") != v.issuer {
		return Claims{}, ErrIssuerMismatch
	}

	audiences := extractAudiences(mapClaims["aud"])
	if v.audience != "" {
		matched := false
		for _, a := range audiences {
			if a == v.audience {
				matched = true
				break
			}
		}
		if !matched {
			return Claims{}, ErrAudienceMismatch
		}
	}

	out := Claims{
		Subject:   sub,
		Issuer:    iss,
		Audiences: audiences,
	}
	if exp, ok := numericDate(mapClaims["exp"]); ok {
		out.ExpiresAt = exp
	}
	if iat, ok := numericDate(mapClaims["iat"]); ok {
		out.IssuedAt = iat
	}
	if nbf, ok := numericDate(mapClaims["nbf"]); ok {
		out.NotBefore = nbf
	}
	return out, nil
}

func extractAudiences(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0).UTC(), true
	case int64:
		return time.Unix(x, 0).UTC(), true
	}
	return time.Time{}, false
}

// BearerToken extracts a `Bearer <token>` value from an Authorization header.
func BearerToken(authHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", ErrTokenMissing
	}
	tok := strings.TrimSpace(authHeader[len(prefix):])
	if tok == "" {
		return "", ErrTokenMissing
	}
	return tok, nil
}
