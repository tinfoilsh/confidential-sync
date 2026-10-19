# Development

None of the local commands need real Clerk, Postgres, AWS, or the production control plane.

Run the unit tests:

```sh
go test ./...
```

Run the adversarial smoke suite when touching crypto, auth, or sync paths. Each test's comment states the invariant it guards:

```sh
go test -tags=smoke -count=1 -v ./internal/localstack/smoke
```

Run a single smoke test:

```sh
go test -tags=smoke -count=1 -v -run TestT08 ./internal/localstack/smoke
```

Start the enclave against an in-memory control plane and fake JWKS issuer. It prints a JWT, an encryption key, and curl examples; state is lost on restart. Override ports with `LISTEN_ENCLAVE`, `LISTEN_CP`, and `LISTEN_JWKS`:

```sh
go run ./cmd/local-stack
```

Run against real upstreams:

```sh
export CLERK_ISSUER="https://clerk.tinfoil.sh"
export CONTROLPLANE_URL="https://api.tinfoil.sh"
export SYNC_ENCLAVE_SECRET="your-shared-service-secret"
go run .
```

When adding a route, also add it to the shim `paths` allowlist in [tinfoil-config.yml](tinfoil-config.yml); a test fails if the two drift.
