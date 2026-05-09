# QRFS Test Vectors

This directory contains the **official byte-level reference vectors** for the QRFS
on-wire format.  They are the authoritative source of truth for the format versions
documented in `docs/FORMAT.md`.

---

## What this directory is

Every file here is a fixed, immutable reference that a conforming QRFS implementation
must be able to produce or consume.  The SHA-256 of each file is recorded in
`manifest.json`.

For `deterministic: true` files, regenerating the vectors from the same fixtures
must produce byte-for-byte identical output.  Any difference is a **format break**
and must be treated as such.

---

## Stability guarantees

Vectors are pinned to specific format versions:

| Layer     | Version |
|-----------|---------|
| `QFSP`    | 1       |
| `QFSC`    | 6       |
| `QRC`     | 3       |

**Any byte change to a `deterministic: true` file is a format break.**  If the
format must change, bump the relevant version number and create a new directory
(e.g. `tests/vectors_v2/`) rather than modifying files in this directory.

---

## Directory structure

```
tests/vectors/
├── README.md               ← this file
├── manifest.json           ← SHA-256 + metadata for every file below
├── inputs/                 ← raw input files fed to the encoder
│   ├── empty.bin           # 0 bytes
│   ├── one_byte.bin        # 1 byte: 0x41 ('A')
│   ├── small_text.txt      # fixed ASCII text, ends with \n
│   ├── utf8_emoji.txt      # UTF-8 text with emoji and non-Latin scripts
│   ├── incompressible.bin  # 4096 bytes from random.Random(0xC0FFEE)
│   └── compressible.bin    # 4096 bytes: (b"QRFS_PATTERN" * 342)[:4096]
├── packaged/               ← QFSP v1 payloads (one per input)
│   └── <name>.qfsp
├── envelopes/
│   ├── clear/              ← QFSC mode 0 (no encryption, no signing)
│   ├── clear_signed/       ← QFSC mode 0 + Ed25519 signature
│   ├── password_interactive/ ← QFSC mode 1 (interactive KDF profile)
│   ├── password_default/     ← QFSC mode 1 (default KDF profile)
│   ├── password_sensitive/   ← QFSC mode 1 (sensitive KDF profile)
│   └── pubkey/             ← QFSC mode 2 (fixed recipient X25519 keypair)
├── chunks/
│   ├── small_text/         ← QRC chunks of envelopes/clear/small_text.qfsc
│   └── small_text_fec_xor/ ← same with FEC=xor, group_size=3
└── keys/
    ├── recipient_x25519.sk ← 32 bytes, raw X25519 private key
    ├── recipient_x25519.pk ← 32 bytes, derived X25519 public key
    ├── signer_ed25519.sk   ← 32 bytes, Ed25519 seed
    └── signer_ed25519.pk   ← 32 bytes, Ed25519 verify key
```

---

## Fixed fixtures

These values are embedded in `generate.py` and recorded in `manifest.json["fixtures"]`.
An external implementer needs them to reproduce or verify decryption.

| Fixture                    | Value                                              |
|----------------------------|----------------------------------------------------|
| `file_id_hex`              | `00112233445566778899aabbccddeeff`                 |
| `argon2_salt_hex`          | `0123456789abcdef0123456789abcdef`                 |
| `aes_gcm_nonce_hex`        | `deadbeefcafebabedeadbeef`                         |
| `password`                 | `correct horse battery staple xx`                  |
| `kdf_profiles.interactive` | Argon2id, `65536 KiB`, `time=3`, `parallel=1`     |
| `kdf_profiles.default`     | Argon2id, `262144 KiB`, `time=3`, `parallel=1`    |
| `kdf_profiles.sensitive`   | Argon2id, `1048576 KiB`, `time=4`, `parallel=1`   |
| `chunk_size_for_vectors`   | `100`                                              |
| `recipient_x25519.sk`      | `keys/recipient_x25519.sk` — 32 bytes of `0xEC`   |
| `signer_ed25519.sk` (seed) | `keys/signer_ed25519.sk` — 32 bytes of `0xED`     |

The input file recipes:

- **`incompressible.bin`** — `random.Random(0xC0FFEE).randint(0, 255)` called 4096 times.
- **`compressible.bin`** — `(b"QRFS_PATTERN" * 342)[:4096]`.

---

## How to regenerate

```bash
python tests/vectors/generate.py
```

Run this only when you are intentionally changing the format (e.g. bumping `QFSC`
to version 6).  You almost never should.

After regeneration, re-run the conformance test to confirm the new vectors are
self-consistent:

```bash
pytest tests/test_vectors.py -v
```

**Do not regenerate vectors as part of a routine refactor.**  The whole point of
this directory is that the bytes are immutable.

---

## Why pubkey mode is non-deterministic

PyNaCl's `SealedBox.encrypt()` generates a random ephemeral X25519 keypair
internally and provides no public API to inject a fixed one.  As a result,
`envelopes/pubkey/*.qfsc` files change on every regeneration.

**How the conformance test handles this:**

- `envelopes/pubkey/*.qfsc` files are marked `"deterministic": false` in
  `manifest.json`.
- `test_deterministic_files_match_recorded_sha256` skips non-deterministic files.
- `test_pubkey_envelopes_decrypt_with_fixed_recipient` verifies that each pubkey
  envelope decrypts correctly using `keys/recipient_x25519.sk`, but does not
  compare the envelope bytes.

The three other modes (`clear`, `clear_signed`, `password_*`) ARE fully
byte-deterministic when given the same fixtures.

---

## How to consume the vectors from another language

1. Read `manifest.json`.  The `"files"` array lists every vector file with its
   path (relative to this directory), SHA-256, size, and `"deterministic"` flag.
2. For `deterministic: true` files, verify the SHA-256 before using the file.
3. Read `"fixtures"` for the decryption parameters (password, salt, nonce,
   Argon2id settings, key file paths).
4. Use `keys/recipient_x25519.sk` (raw 32-byte X25519 private key) to decrypt
   `envelopes/pubkey/*.qfsc`.
5. Use `keys/signer_ed25519.pk` (raw 32-byte Ed25519 verify key) to verify
   signatures on `envelopes/clear_signed/*.qfsc`.

The on-wire format is fully described in `docs/FORMAT.md`.
