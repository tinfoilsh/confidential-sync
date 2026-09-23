# Confidential Sync

Tinfoil's sync enclave encrypts and stores chat backups for [Tinfoil Chat](https://chat.tinfoil.sh). Clients keep their encryption keys and send them with each request; the enclave seals and unseals data inside the confidential VM and stores only ciphertext, so neither Tinfoil nor the storage layer can read chats.

## How it works

For each request the enclave:

1. Verifies the caller's Clerk JWT
2. Encrypts or decrypts the blob with the client-supplied key using AES-GCM, binding the ciphertext to the user, scope, and blob id
3. Stores or fetches ciphertext through the control plane (chat data) or the buckets sidecar (attachments)
4. Discards the key and plaintext when the request completes

The enclave is stateless and never persists key material. Writes are guarded by compare-and-set so concurrent devices cannot overwrite each other.

User-facing behavior is documented at [docs.tinfoil.sh/chat/cloud-sync](https://docs.tinfoil.sh/chat/cloud-sync). The route table is in [internal/server/](internal/server/) and mirrored by the shim allowlist in [tinfoil-config.yml](tinfoil-config.yml); a test fails if the two drift.

## Running locally

```bash
export CLERK_ISSUER="https://clerk.tinfoil.sh"
export CONTROLPLANE_URL="https://api.tinfoil.sh"
export SYNC_ENCLAVE_SECRET="your-shared-service-secret"

go run .
```

For development without real upstreams, `go run ./cmd/local-stack` starts an in-process control plane, JWKS issuer, and minted credentials. See [LOCAL_TESTING.md](LOCAL_TESTING.md) for the full runbook.

## Architecture Overview

- **[internal/server/](internal/server/)**: HTTP routes for sync, keys, attachments, sharing, and migration
- **[internal/auth/](internal/auth/)**: Clerk JWT verification
- **[internal/crypto/](internal/crypto/)**, **[internal/envelope/](internal/envelope/)**: AES-GCM sealing and the blob envelope format
- **[internal/controlplane/](internal/controlplane/)**, **[internal/buckets/](internal/buckets/)**: Ciphertext storage clients
- **[internal/searchindex/](internal/searchindex/)**: Encrypted search indexes
- **[cmd/local-stack/](cmd/local-stack/)**: Local development harness

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for the full text.
