package localstack

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/server"
)

// Config tunes the stack's listeners. Empty strings mean ephemeral
// ports (127.0.0.1:0) — preferred for tests because they avoid port
// collisions when many test binaries run in parallel.
type Config struct {
	EnclaveAddr string
	CPAddr      string
	JWKSAddr    string
}

// Stack is a running 3-listener test stack. Stop releases all listeners
// and shuts down the HTTP servers cleanly.
type Stack struct {
	EnclaveURL string
	CPURL      string
	JWKSURL    string

	CP *StubCP

	// SigningKey + SigningKID let test code mint JWTs with arbitrary
	// claims (different subs, expired exp, swapped alg, etc.) to
	// drive auth-boundary tests.
	SigningKey *rsa.PrivateKey
	SigningKID string
	Issuer     string

	enclaveSrv *http.Server
	cpSrv      *http.Server
	jwksSrv    *http.Server
}

// Start brings up the three listeners and returns a handle. It is the
// caller's responsibility to call Stop.
func Start(cfg Config) (*Stack, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa: %w", err)
	}
	signKID := "local-stack-kid"
	pub := priv.Public().(*rsa.PublicKey)
	jwksJSON, _ := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": signKID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})

	jwksMux := http.NewServeMux()
	jwksMux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	})
	jwksLn, err := listen(cfg.JWKSAddr)
	if err != nil {
		return nil, fmt.Errorf("listen jwks: %w", err)
	}
	jwksURL := "http://" + jwksLn.Addr().String()
	jwksSrv := &http.Server{Handler: jwksMux}
	go func() { _ = jwksSrv.Serve(jwksLn) }()

	cp := NewStubCP()
	cpLn, err := listen(cfg.CPAddr)
	if err != nil {
		_ = jwksSrv.Close()
		return nil, fmt.Errorf("listen cp: %w", err)
	}
	cpURL := "http://" + cpLn.Addr().String()
	cpSrv := &http.Server{Handler: cp}
	go func() { _ = cpSrv.Serve(cpLn) }()

	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL + "/.well-known/jwks.json"})
	if err != nil {
		_ = jwksSrv.Close()
		_ = cpSrv.Close()
		return nil, fmt.Errorf("keyfunc: %w", err)
	}
	verifier, err := auth.NewVerifierWithKeyfunc(auth.Config{Issuer: jwksURL}, kf)
	if err != nil {
		_ = jwksSrv.Close()
		_ = cpSrv.Close()
		return nil, fmt.Errorf("verifier: %w", err)
	}
	cpClient := controlplane.NewClient(cpURL, &http.Client{Timeout: 10 * time.Second})
	bucketsClient := buckets.NewClient(cpURL, BucketsStubAPIKey, &http.Client{Timeout: 10 * time.Second})
	handler := server.NewHandler(server.Deps{Controlplane: cpClient, Buckets: bucketsClient, GitSHA: "local-stack"}, verifier, nil)

	enclaveLn, err := listen(cfg.EnclaveAddr)
	if err != nil {
		_ = jwksSrv.Close()
		_ = cpSrv.Close()
		return nil, fmt.Errorf("listen enclave: %w", err)
	}
	enclaveURL := "http://" + enclaveLn.Addr().String()
	enclaveSrv := &http.Server{
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      server.MigrateAllRequestTimeout,
	}
	go func() { _ = enclaveSrv.Serve(enclaveLn) }()

	return &Stack{
		EnclaveURL: enclaveURL,
		CPURL:      cpURL,
		JWKSURL:    jwksURL,
		CP:         cp,
		SigningKey: priv,
		SigningKID: signKID,
		Issuer:     jwksURL,
		enclaveSrv: enclaveSrv,
		cpSrv:      cpSrv,
		jwksSrv:    jwksSrv,
	}, nil
}

// Stop shuts down the three HTTP servers.
func (s *Stack) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.enclaveSrv != nil {
		_ = s.enclaveSrv.Shutdown(ctx)
	}
	if s.cpSrv != nil {
		_ = s.cpSrv.Shutdown(ctx)
	}
	if s.jwksSrv != nil {
		_ = s.jwksSrv.Shutdown(ctx)
	}
}

// MintJWT signs an RS256 JWT with `sub`, valid for the supplied
// duration. Test code uses this to drive cross-user isolation
// (different subs) and auth-boundary attacks (negative durations,
// swapped alg).
func (s *Stack) MintJWT(sub string, lifetime time.Duration) (string, error) {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iss": s.Issuer,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	})
	tok.Header["kid"] = s.SigningKID
	return tok.SignedString(s.SigningKey)
}

// MintJWTRaw signs a JWT with arbitrary claims and a chosen signing
// method. Used by T11 (alg confusion: HS256 signed with the RSA
// public key bytes) and T24 (wrong issuer).
func (s *Stack) MintJWTRaw(method jwt.SigningMethod, claims jwt.MapClaims, kid string, secret any) (string, error) {
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	return tok.SignedString(secret)
}

func listen(addr string) (net.Listener, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return net.Listen("tcp", addr)
}

// ErrShutdown is the sentinel returned when Stop has been called.
var ErrShutdown = errors.New("localstack: shutdown")
