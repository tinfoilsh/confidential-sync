# Confidential Sync Enclave

Tinfoil enclave that owns all encryption and cloud-sync orchestration for the
Tinfoil chat clients. Clients keep their encryption keys and passkeys locally
and delegate every sync operation (upload, fetch, decrypt) to this enclave.

The enclave is stateless: it receives the keys it needs on each request,
performs the encryption or decryption inside the confidential VM, proxies the
ciphertext to or from the Tinfoil controlplane, and forgets everything when
the request finishes.

## Status

Scaffolding only. Implementation in progress.
