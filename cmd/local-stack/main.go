// Local-stack daemon: spins up the enclave + a stub controlplane + a
// fake JWKS issuer on real ports, prints a ready-to-use JWT + CEK, and
// blocks until SIGINT/SIGTERM. Intended for curl-driven debugging.
// The same plumbing is shared with the smoke test suite under
// internal/localstack/smoke; do not duplicate logic here.
//
//	go run ./cmd/local-stack
//
// Override ports with LISTEN_ENCLAVE / LISTEN_CP / LISTEN_JWKS.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/localstack"
)

func main() {
	cfg := localstack.Config{
		EnclaveAddr: envDefault("LISTEN_ENCLAVE", "127.0.0.1:8089"),
		CPAddr:      envDefault("LISTEN_CP", "127.0.0.1:8088"),
		JWKSAddr:    envDefault("LISTEN_JWKS", "127.0.0.1:8087"),
	}
	userSub := envDefault("USER_SUB", "user_local")

	stack, err := localstack.Start(cfg)
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	defer stack.Stop()

	jwtStr, err := stack.MintJWT(userSub, 24*time.Hour)
	if err != nil {
		log.Fatalf("mint jwt: %v", err)
	}

	cek := make([]byte, crypto.KeySize)
	if _, err := rand.Read(cek); err != nil {
		log.Fatalf("generate cek: %v", err)
	}
	kidBytes, _ := crypto.DeriveKeyID(cek)
	cekKID := crypto.KeyIDHex(kidBytes)
	cekB64 := base64.StdEncoding.EncodeToString(cek)

	fmt.Println()
	fmt.Println("local-stack ready")
	fmt.Println("=================")
	fmt.Printf("enclave         %s\n", stack.EnclaveURL)
	fmt.Printf("controlplane    %s  (stub)\n", stack.CPURL)
	fmt.Printf("jwks            %s/.well-known/jwks.json\n", stack.JWKSURL)
	fmt.Printf("user_sub        %s\n", userSub)
	fmt.Printf("cek_key_id      %s\n", cekKID)
	fmt.Printf("cek_b64         %s\n", cekB64)
	fmt.Println()
	fmt.Println("export TOK='" + jwtStr + "'")
	fmt.Println("export CEK='" + cekB64 + "'")
	fmt.Println("export BASE='" + stack.EnclaveURL + "'")
	fmt.Println()
	fmt.Println("# Try it:")
	fmt.Println("  curl -sS $BASE/v1/health")
	fmt.Println("  curl -sS -X POST $BASE/v1/key/register \\")
	fmt.Println("    -H \"Authorization: Bearer $TOK\" \\")
	fmt.Println("    -H 'Content-Type: application/json' \\")
	fmt.Println("    -d '{\"key\":\"'$CEK'\",\"if_match\":\"*\",\"created_via\":\"start_fresh\",\"idempotency_key\":\"local-1\"}'")
	fmt.Println()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutdown signal received")
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
