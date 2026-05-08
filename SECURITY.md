# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security or cryptographic bugs.**

Use GitHub's private vulnerability reporting instead:

👉 [Open a private security advisory](https://github.com/flyingsurveyor/qrfs/security/advisories/new)

Describe the issue, the affected component, and — if possible — a minimal
reproduction. We aim to acknowledge reports within **7 days** and to provide an
initial assessment or fix timeline within **14 days**.

---

## Scope

This security policy covers code in `qrfs/core/` and `qrfs/routes/`.

The browser-based scanner (`qrfs/static/vendor/html5-qrcode-2.3.8.min.js`) is a
vendored third-party library. Its security status is tracked separately in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Please report vulnerabilities
in that library to its upstream maintainers.

---

## Threat model

### What QRFS protects against

- **Confidentiality of the encoded payload** at rest on physical media. An
  adversary who obtains the printed QR pages but not the password or private key
  cannot recover the plaintext.
- **Integrity of the payload.** AES-256-GCM authenticates the entire transport
  header as additional authenticated data (AAD); any tampering with the header or
  ciphertext will cause decryption to fail.
- **Optional sender authentication.** When Ed25519 signing is enabled, the
  receiver can verify that the payload was produced by the holder of a specific
  signing key. The signature covers the complete unsigned transport blob.

### What QRFS does NOT protect against

- **Coercion of the key holder.** QRFS provides no plausible-deniability or
  duress-signal mechanism. An adversary with physical or legal coercive power over
  the holder can compel disclosure of the password or private key.
- **Physical destruction or partial loss beyond FEC capacity.** Reed-Solomon and
  XOR FEC can recover from the loss of up to `P` QR codes per group. Losses
  exceeding that threshold result in unrecoverable data.
- **Side-channel attacks on the encoding or decoding device.** Argon2id and
  AES-256-GCM are run on the local host without any timing or power-analysis
  countermeasures beyond what the underlying libraries provide.
- **Metadata leakage in clear mode.** In clear mode (`mode = 0`), the `QFSP`
  header fields — filename, MIME type, and original size — are transported in
  cleartext. In password or public-key mode these fields are inside the
  AES-256-GCM envelope and are therefore confidential.
- **Traffic analysis on the local Flask server.** QRFS binds to `0.0.0.0` by
  default. On a shared or networked host, the web interface is reachable by anyone
  on the local network. Use a firewall or bind to `127.0.0.1` if this is a
  concern.
- **Supply-chain attacks on dependencies.** QRFS relies on `cryptography`,
  `PyNaCl`, `Flask`, `reportlab`, `pyzbar`, and other third-party packages. A
  compromised upstream dependency could undermine all security guarantees.
- **Quantum adversaries.** X25519 key exchange and AES-256-GCM are not
  post-quantum. A sufficiently capable quantum computer could break the
  confidentiality of public-key-encrypted payloads.

---

## Cryptographic primitives

All primitives are used as provided by well-audited libraries (`cryptography`,
`PyNaCl` / libsodium). No cryptographic algorithms are implemented from scratch.

| Primitive | Role | Rationale |
|-----------|------|-----------|
| **Argon2id** (libsodium) | Password-based key derivation | Memory-hard; recommended by OWASP for password hashing and KDFs. Current parameters: `opslimit = 3`, `memlimit = 64 MiB`, output 32 bytes. |
| **AES-256-GCM** | Authenticated encryption of the payload | Widely deployed AEAD construction; hardware-accelerated on most platforms. The full `QFSC` transport header is passed as AAD, binding the ciphertext to its metadata. |
| **X25519 SealedBox** (libsodium) | Public-key encryption of a random session key | Ephemeral key agreement; the sender learns nothing about the recipient's private key. |
| **Ed25519** | Detached digital signatures | Fast, small signatures; deterministic (no per-signature randomness required). |
| **SHA-256** | `key_id` derivation | `key_id = SHA-256(pubkey)[:8]` identifies the intended recipient key without exposing the full key in the chunk header. |

Nonce / salt generation uses `os.urandom` (via the `cryptography` library) for
all cryptographic randomness.

---

## Known limitations and future hardening

- **Argon2id parameters are currently the libsodium "moderate" defaults**
  (`opslimit = 3`, `memlimit = 64 MiB`). These provide reasonable protection on
  2024-era hardware but are not tuned for long-term archival against well-resourced
  adversaries. A future `--paranoid` or `--archival` mode with stronger parameters
  (e.g. `opslimit = 8`, `memlimit = 512 MiB`) is planned and will be documented
  in `docs/FORMAT.md` when implemented.
- **No key rotation story for long-term archives.** A QRFS archive encrypted to a
  public key is tied to the corresponding private key for its entire lifetime.
  There is currently no re-encryption or key-rotation mechanism. Users should
  archive the private key alongside the physical media or in a separate secure
  location.
- **AES-GCM nonce uniqueness.** Each QRFS encode operation generates a fresh
  random salt (for Argon2id) and a fresh random nonce (for AES-GCM). Because the
  AES key is derived from both the password and the salt, nonce reuse under the
  same key is not a realistic concern in normal operation.
