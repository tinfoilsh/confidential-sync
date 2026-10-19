# Confidential Sync

Tinfoil's sync enclave encrypts and stores chat backups for [Tinfoil Chat](https://chat.tinfoil.sh). Clients keep their encryption keys and send them with each request; the enclave seals and unseals data inside the confidential VM and stores only ciphertext, so neither Tinfoil nor the storage layer can read chats.

User-facing behavior is documented at [docs.tinfoil.sh/chat/cloud-sync](https://docs.tinfoil.sh/chat/cloud-sync).

## Development

```bash
go test ./...
go run ./cmd/local-stack
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the smoke suite and running against real upstreams.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for the full text.
