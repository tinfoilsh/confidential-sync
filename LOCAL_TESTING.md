# Local Testing

This repo ships three layers of self-contained tests. None of them
need real Clerk, real Postgres, real AWS, or the production
controlplane. The build tag splits the heavy harness from the fast
unit suite so day-to-day work stays sub-second.

## TL;DR

```sh
# 1. Fast unit tests (always run on every change)
go test ./...

# 2. Adversarial end-to-end smoke suite (when touching crypto/sync paths)
go test -tags=smoke -v ./internal/localstack/smoke

# 3. Live curl-able daemon (manual debugging)
go run ./cmd/local-stack
```

All three share the same in-process scaffolding under
`internal/localstack/` — a stub controlplane, a fake JWKS issuer,
and a helper that wires the real enclave handler against them.

---

## Layer 1 — Unit tests (`go test ./...`)

The standard Go test suite under `internal/{auth,controlplane,crypto,envelope,server}`.
Roughly 17 packages worth of in-memory tests covering AEAD primitives,
envelope canonicalisation, AAD construction, JWT verification, op-hash
binding, etc. These are the first line of defence; they run in ~1.5s
and should pass on every commit.

If you touch a `*.go` file under `internal/`, run this first.

---

## Layer 2 — Adversarial smoke suite (`go test -tags=smoke ...`)

Path: `internal/localstack/smoke/`. Build-tagged because each test
spins up three HTTP listeners (enclave, stub controlplane, fake
JWKS) on ephemeral ports.

Every test is shaped around three questions:

1. **Adversary model.** Who is attacking, and what do they have
   access to? (DB read, DB write, JWKS read, stolen CEK, etc.)
2. **Invariant attacked.** Which property of the enclave's design
   does the test try to break?
3. **Regression caught.** What concrete code change would make the
   test fail?

If a test cannot answer all three crisply, it is theatre and gets
deleted. The smoke suite is intentionally small (13 tests) for this
reason — adding more requires identifying a fresh invariant that
isn't already exercised by either the unit tests or one of the 13.

### Test inventory

| ID  | Test                                | Invariant                                         | Adversary model                                              |
| --- | ----------------------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| T01 | CiphertextHidesPlaintext            | v2 ciphertext at rest is opaque                   | DB read-replica leak: grep stored bytes for plaintext        |
| T02 | TamperedCiphertextRejected          | AES-GCM rejects every single-byte mutation        | DB write: flip bits to alter unsealed plaintext              |
| T03 | AADBindsScope                       | AAD includes scope; cross-scope blob → fail       | DB write: move chat blob into project slot                   |
| T04 | AADBindsUserSub                     | AAD includes clerk_user_id from verified JWT      | User B steals user A's CEK + presents own JWT                |
| T05 | AADBindsID                          | AAD includes id; cross-id swap → fail             | DB write: overwrite blob Y with blob X's bytes               |
| T06 | CASPreventsConcurrentOverwrite      | Stale if_match → 409 SYNC_CONFLICT, no overwrite  | Two tabs racing a chat update                                |
| T08 | DeleteNullIfMatchRetriesOnRace      | §16.6 retry loop absorbs a concurrent push        | One-shot push lands between enclave's GET and DELETE         |
| T09 | AuthMissingBearerRejected           | Auth middleware mandatory on /v1/sync             | Route wired without authMiddleware                           |
| T10 | AuthExpiredJWTRejected              | exp claim enforced                                | Stolen-but-expired token                                     |
| T11 | AuthAlgConfusionRejected            | Pinned alg + typed-key keyfunc blocks HS256-vs-RSA | Classic alg-confusion JWT forgery                            |
| T12 | LegacyV0BlobReturnsNeedsRewrap      | Pull on a v0 envelope returns plaintext + flag    | Pre-cutover blob lingering after the migration               |
| T13 | MigrateLegacyToV2Roundtrip          | Migrate rewraps without altering plaintext        | Re-seal corruption would surface as a different byte string  |
| T14 | PullWrongCEKReturnsOKFalseNoPlaintext | Wrong CEK → ok:false, no plaintext field, no 5xx  | Buggy/malicious client supplies wrong key bytes              |

The mapping back to source files is one-to-one:

```
smoke/crypto_test.go   T01 T02
smoke/aad_test.go      T03 T04 T05
smoke/cas_test.go      T06
smoke/delete_test.go   T08
smoke/auth_test.go     T09 T10 T11
smoke/legacy_test.go   T12 T13
smoke/wrong_cek_test.go T14
```

### Verifying that the tests actually catch regressions

The point of the suite is to fail when a regression lands. Two
deliberate-break checks have been performed and documented:

- **T08:** setting `deleteMaxRetries = 1` in `internal/server/ops.go`
  causes T08 to fail with `delete_exhausted_retries`. With the
  shipped value of `3` the test passes. The retry loop is therefore
  the load-bearing piece T08 is guarding.
- **T11:** widening `WithValidMethods` to include `HS256` does NOT
  break T11 because the `keyfunc` returns a typed `*rsa.PublicKey`,
  which the jwt library refuses to use as an HMAC secret. T11
  therefore guards the deeper defence (typed keyfunc). To regress
  T11, both the alg pin AND the keyfunc would need to be
  weakened — a useful "defense in depth" canary.

### Running selectively

```sh
# All 13
go test -tags=smoke -v -count=1 ./internal/localstack/smoke

# A specific test
go test -tags=smoke -v -run TestT08 -count=1 ./internal/localstack/smoke

# Verbose-on-failure only
go test -tags=smoke -count=1 ./internal/localstack/smoke
```

`-count=1` disables Go's test result cache — important when
iterating because the suite touches HTTP listeners and the cache
otherwise hides recompiles.

---

## Layer 3 — Live daemon (`go run ./cmd/local-stack`)

Spins up the same three listeners as the smoke suite but on fixed
ports (defaults: enclave 8089, stub-CP 8088, JWKS 8087) and blocks
until SIGINT. Prints a ready-to-use JWT + CEK + base URL with
copy-pasteable `export` lines and a curl example.

Use this when you want to manually probe an endpoint, attach a
debugger, or reproduce a wire-level issue caught in production logs.

### Defaults

| Env var          | Default          | Meaning                          |
| ---------------- | ---------------- | -------------------------------- |
| `LISTEN_ENCLAVE` | `127.0.0.1:8089` | Public enclave HTTP listener     |
| `LISTEN_CP`      | `127.0.0.1:8088` | Stub controlplane listener       |
| `LISTEN_JWKS`    | `127.0.0.1:8087` | Fake JWKS for `iss` resolution   |
| `USER_SUB`       | `user_local`     | `sub` claim baked into the JWT   |

### Example session

```sh
$ go run ./cmd/local-stack
local-stack ready
=================
enclave         http://127.0.0.1:8089
controlplane    http://127.0.0.1:8088  (stub)
jwks            http://127.0.0.1:8087/.well-known/jwks.json
user_sub        user_local
cek_key_id      a8d3c7...
cek_b64         WkRxc1Z2N3l...
export TOK='eyJhbGciOi...'
export CEK='WkRxc1Z2N3l...'
export BASE='http://127.0.0.1:8089'

# Try it:
  curl -sS $BASE/v1/health
  curl -sS -X POST $BASE/v1/key/register \
    -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' \
    -d '{"key":"'$CEK'","if_match":"*","created_via":"start_fresh","idempotency_key":"local-1"}'
```

The stub controlplane has no persistence — restarting the daemon
wipes all state. That's a feature: every session is clean.

---

## Shared scaffolding (`internal/localstack/`)

`stack.go` — `Start(Config) (*Stack, error)` returns three URLs and a
JWT-minting handle. The daemon and the smoke fixture both call this.

`stub_cp.go` — in-memory controlplane mirroring `/api/sync/*` and
`/api/keys/*` with CAS, list-status, needs-migration, and rewrap. A
small "test poke" API (`PeekBlob`, `SetBlob`, `CopyBlob`,
`OnFirstDelete`) lets adversarial tests inject failure modes (T02,
T03, T05, T08) that cannot be expressed through the regular HTTP
surface.

`smoke/fixture.go` — per-test scaffold: starts a fresh stack,
generates a CEK, registers it, and exposes typed helpers
(`push`, `pullOne`, `deleteRow`, `migrate`).

When adding a new smoke test, prefer using existing helpers and the
test-poke API over reaching into the stub's internals — the
test-poke surface is intentionally small and reviewed.
