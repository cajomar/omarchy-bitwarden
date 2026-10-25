# ADR 0023: mTLS Client Certificate Authentication for Self-Hosted Gateways

## Status
Accepted

## Context
Self-hosted Bitwarden and Vaultwarden instances in enterprise, homelab, and private network deployments are frequently placed behind edge security gateways and reverse proxies (such as Cloudflare Access, Envoy, Nginx, or Caddy) enforcing mutual TLS (mTLS) client certificate authentication. In these architectures, presenting a valid client certificate is an essential part of the edge authentication boundary: without it, the edge gateway answers with HTTP 403 Forbidden or aborts the TLS handshake immediately.

While ADR 0021 adopted the host operating system certificate trust store for server validation (`rustls-tls-native-roots`), `omawarden` previously provided no mechanism to present client certificates during TLS handshakes.

Furthermore, several technical and security constraints had to be addressed:
1. **Engine Purity & Lightweight Footprint**: Following ADR 0021, `omawarden` strictly utilizes `reqwest` with pure `rustls-tls-native-roots`. `rustls` does not read the browser NSS database (`~/.pki/nssdb`) and does not natively parse PKCS#12 (`.p12`) archives without additional complex C/OpenSSL or heavy third-party dependencies.
2. **Server Switching & Origin Isolation**: In accordance with ADR 0008, switching server URLs purges ephemeral session tokens and vault caches. However, enterprise mTLS credentials belong to specific domains. Purging client certificate file paths upon switching away to official cloud instances creates severe user friction when switching back, while presenting client certificates globally to arbitrary endpoints leaks enterprise identity.
3. **Local Security Boundaries**: Client private keys stored on disk must adhere to Rule 5 of the Security Handbook (Atomic Least-Privilege File Permissions `0600`), and reject degraded/weak cryptographic keys (as highlighted by recent industry zero-day disclosures such as the eMudhra weak-key incident).
4. **Rejection of In-App CA Injection**: Application-level custom server CA bundles (`--ca-cert`) must be categorically rejected to prevent unprivileged configuration poisoning attacks against master password hashes and authentication tokens. Server trust strictly defers to the OS-managed trust store (ADR 0021).

## Decision
1. **Native PEM Client Identity via rustls**:
   - `omawarden` natively supports client identities in standard PEM format (X.509 certificate chain with unencrypted PKCS#8, PKCS#1, or SEC1 private key) using `reqwest::Identity::from_pem`.
   - Users may provide a single combined PEM file (`client_cert_path`) or separate certificate and key files (`client_key_path`). PKCS#12 (`.p12`) archives are converted via standard tooling (`openssl pkcs12 -in client.p12 -out client.pem -nodes`).

2. **Configuration Schema and Non-Destructive Server Switching**:
   - `Config` in `config.json` is extended with:
     - `client_cert_path: Option<String>`
     - `client_key_path: Option<String>`
     - `client_cert_server: Option<String>`
   - When configured via `omawarden config set --client-cert <PATH> [--client-key <PATH>]`, the active `server_url` RFC 6454 origin (`scheme://host:port`) is automatically recorded as `client_cert_server`.
   - Clearing is executed explicitly via `omawarden config set --client-cert ""`.
   - Unlike session tokens (purged per ADR 0008), client certificate configurations are preserved across `server_url` changes.

3. **RFC 6454 Same-Origin Gating**:
   - In the centralized HTTP client factory (`build_http_client_with_context`), `omawarden` evaluates `is_same_origin(target_url, client_cert_server)`.
   - The client certificate is loaded and presented **only** when communicating with the designated origin. Requests to unrelated endpoints (e.g. `vault.bitwarden.com` or third-party attachment CDNs) proceed over standard TLS without presenting client credentials.

4. **Fail-Closed Permission and Key Strength Gates**:
   - On POSIX platforms, private key files with permissions wider than `0600` or `0400` (i.e. `mode & 0o077 != 0`) fail closed immediately with an actionable error.
   - Private key structures are validated to reject degraded keys (RSA < 2048 bits or degenerate elliptic curve parameters).
   - Missing or corrupted certificate files on matching origins fail closed immediately without silent fallback.

5. **Strict Adherence to ADR 0021 (No Application-Level CA Override)**:
   - Server-side CA trust validation continues to rely strictly on the host operating system trust store (`/etc/ca-certificates/`). No `--ca-cert` application flag or configuration key is accepted.

## Consequences
- **Zero-Friction Gateway Access**: Users with self-hosted Vaultwarden / Bitwarden instances behind mTLS gateways can log in, sync, download attachments, and run health checks seamlessly.
- **Architectural Purity**: Retains 100% pure Rust `rustls-tls-native-roots` without adding OpenSSL C bindings or heavyweight PKCS#12 crates.
- **Defense-in-Depth**: Private key permissions are strictly audited on disk, weak keys are rejected, and credentials are never exposed across foreign origins or in diagnostic logs.
