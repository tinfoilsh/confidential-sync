# Confidential Sync Enclave

A Tinfoil enclave that owns all encryption and cloud-sync orchestration for the Tinfoil chat clients. Clients keep their encryption keys and passkeys locally and delegate every sync operation (push, pull, decrypt) to this enclave.

The enclave is stateless: it receives the keys it needs on each request, performs the encryption or decryption inside the confidential VM, proxies the ciphertext to or from the Tinfoil controlplane, and forgets everything when the request finishes.

The enclave exposes an HTTP surface for sync, key management, blob migration, attachment transfer, and chat sharing:

- `POST /v1/sync/*` - push, pull, list, and delete encrypted blobs
- `POST /v1/key/*` - register and rotate per-account encryption keys
- `POST /v1/blobs/migrate*` - rewrap legacy blobs into the current envelope format
- `POST /v1/attachment/*` - store and fetch encrypted attachments via the buckets sidecar
- `POST /v1/share/*` - seal and open shared chats
- `GET /health`, `GET /v1/health` - health checks

## Architecture

```text
Chat client (web / mobile)
  │  HTTP + Bearer JWT (Clerk), client-held key bytes in body
  ▼
┌──────────────────────────────────────────────┐
│            Tinfoil CVM shim (:443)            │
│        path allowlist → upstream :8089        │
└──────────────────────┬───────────────────────┘
                       ▼
        ┌──────────────────────────────────────┐
        │ Sync enclave                         │
        │ - JWT verification (Clerk JWKS)      │
        │ - AES-GCM seal / unseal in-enclave   │
        │ - AAD binds scope, user, blob id     │
        │ - CAS to prevent lost updates        │
        └──────┬───────────────────────┬───────┘
               ▼                       ▼
     ┌───────────────┐        ┌───────────────────┐
     │ Controlplane  │        │ Buckets sidecar   │
     │ (ciphertext)  │        │ (attachments, S3) │
     └───────────────┘        └───────────────────┘
```

The enclave never persists plaintext or key material. Ciphertext is stored by the controlplane; attachment bytes are stored through the buckets sidecar. Encryption keys arrive in each request body and are discarded when the request completes.

## Quick Start

The enclave requires a Clerk issuer, a controlplane URL, and a shared service secret:

```bash
export CLERK_ISSUER="https://clerk.tinfoil.sh"
export CONTROLPLANE_URL="https://api.tinfoil.sh"
export SYNC_ENCLAVE_SECRET="your-shared-service-secret"

go run .
```

For local development against an in-process controlplane, JWKS issuer, and minted JWT + key, use the local stack instead of wiring up real upstreams:

```bash
go run ./cmd/local-stack
```

See [`LOCAL_TESTING.md`](./LOCAL_TESTING.md) for the full runbook, including the adversarial smoke suite and the live curl-able daemon.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLERK_ISSUER` | - | Clerk issuer URL used to resolve the JWKS for JWT verification. Required. |
| `CONTROLPLANE_URL` | - | Base URL of the Tinfoil controlplane that stores ciphertext. Required. |
| `SYNC_ENCLAVE_SECRET` | - | Shared service secret used to authenticate the enclave to the controlplane. Required. |
| `CLERK_AUDIENCE` | - | Expected `aud` claim on incoming JWTs. When unset, audience is not enforced. |
| `BUCKETS_URL` | - | Base URL of the buckets sidecar used for attachment storage. When unset, attachment routes return 503 and rewrap / wipe paths skip bucket cleanup. |
| `CHAT_ATTACHMENTS_BUCKET` | - | S3 bucket name sent in the sidecar's path-style request URL. The sidecar routes to whatever bucket the path names, so this must be set alongside `BUCKETS_URL`; when unset the buckets client is treated as unconfigured. |
| `SEARCH_BUCKETS_URL` | - | Base URL of the buckets sidecar used for encrypted search indexes. When unset (or the embedding service is unconfigured), search routes return 503 and push/delete skip index upkeep. |
| `SEARCH_INDEXES_BUCKET` | - | Name of the S3 bucket for search indexes. Required alongside `SEARCH_BUCKETS_URL`. |
| `TINFOIL_API_KEY` | - | API key for the Tinfoil inference service. |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model identifier recorded in the search index. |
| `LISTEN_ADDR` | `:8089` | Address the enclave HTTP server listens on. |
| `GIT_SHA` | `unknown` | Build identifier reported by the health endpoint. Normally injected at build time via `-ldflags`. |

## Endpoints

All `/v1/sync/*`, `/v1/key/*`, `/v1/blobs/*`, `/v1/attachment/put`, `/v1/attachment/delete`, and `/v1/share/seal` routes require a Clerk-issued Bearer JWT in the `Authorization` header. Request and response bodies are JSON.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/sync/push` | yes | Seal a blob and store it via the controlplane, guarded by compare-and-set. |
| `POST` | `/v1/sync/pull` | yes | Fetch and unseal a stored blob. |
| `POST` | `/v1/sync/list-status` | yes | List sync metadata (versions, migration status) for a scope. |
| `POST` | `/v1/sync/delete` | yes | Delete a stored blob, guarded by compare-and-set. |
| `POST` | `/v1/key/register` | yes | Register the per-account content encryption key. |
| `POST` | `/v1/key/add-bundle` | yes | Add a passkey-wrapped key bundle to the account. |
| `POST` | `/v1/key/remove-bundle` | yes | Remove a key bundle from the account. |
| `POST` | `/v1/key/current` | yes | Report the current key id and whether data exists under it. |
| `POST` | `/v1/blobs/migrate` | yes | Rewrap a single legacy blob into the current envelope format. |
| `POST` | `/v1/blobs/migrate-all` | yes | Kick off a detached background job that rewraps every legacy blob. |
| `POST` | `/v1/blobs/migrate-status` | yes | Poll the status of the background migration job. |
| `POST` | `/v1/attachment/put` | yes | Encrypt and store an attachment via the buckets sidecar. |
| `POST` | `/v1/attachment/get` | yes | Fetch and decrypt an attachment. |
| `POST` | `/v1/attachment/delete` | yes | Delete a stored attachment. |
| `POST` | `/v1/attachment/get-public` | no | Fetch a shared attachment using the per-attachment key as the access proof. |
| `POST` | `/v1/share/seal` | yes | Seal a chat for sharing and return a share key. |
| `POST` | `/v1/share/open` | no | Open a shared chat using the share key as the access proof. |
| `GET` | `/health`, `/v1/health` | no | Liveness and build-version check. |

The unauthenticated `get-public` and `share/open` routes use possession of the per-item key as the access proof, mirroring the trust model of the legacy in-browser share path. The exposed path list is kept in lockstep with the CVM shim allowlist in [`tinfoil-config.yml`](./tinfoil-config.yml); a test fails if the two drift.

## Docker

```bash
docker build -t confidential-sync-enclave .
docker run -p 8089:8089 \
  -e CLERK_ISSUER=$CLERK_ISSUER \
  -e CONTROLPLANE_URL=$CONTROLPLANE_URL \
  -e SYNC_ENCLAVE_SECRET=$SYNC_ENCLAVE_SECRET \
  confidential-sync-enclave
```

In production the image runs as the `sync-enclave` container inside a Tinfoil confidential VM alongside the buckets sidecar, fronted by the CVM shim on port 443. See [`tinfoil-config.yml`](./tinfoil-config.yml) for the deployed topology.

## Security

The enclave runs inside a Tinfoil confidential VM, so its memory and execution are shielded from the host. On top of that, the design enforces:

- **In-enclave encryption only.** Plaintext and key bytes exist solely inside the confidential VM for the lifetime of a request and are never persisted.
- **Authenticated encryption with bound context.** Blobs are sealed with AES-GCM whose additional authenticated data binds the scope, the verified Clerk user, and the blob id, so ciphertext cannot be replayed across scopes, users, or rows.
- **Mandatory JWT verification.** Every `/v1/sync` and key-management route verifies a Clerk-issued JWT with a pinned algorithm and a typed key, defeating algorithm-confusion forgeries and expired tokens.
- **Compare-and-set writes.** Push and delete are guarded by `if_match` to prevent lost updates and concurrent overwrites.
- **Shim path allowlist.** The CVM shim hard-blocks any path not declared in `tinfoil-config.yml`, keeping the external attack surface to the audited route list.

Because all processing occurs within the secure enclave, blob contents and key material remain encrypted and inaccessible outside the trusted execution environment.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to legitimate security reports within 24 hours.

## License

This project is licensed under the GNU Affero General Public License v3.0. See [`LICENSE`](./LICENSE) for the full text.
