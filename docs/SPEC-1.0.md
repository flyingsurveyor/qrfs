# QRFS Format Specification — Version 1.0

**Status:** Draft (will become Stable upon QRFS 1.0 release)

**Editors:** flyingsurveyor/qrfs project maintainers

**Date:** 2026-05-09

**Reference implementation:** [`flyingsurveyor/qrfs`](https://github.com/flyingsurveyor/qrfs) Python package

**Conformance test vectors:** `tests/vectors/` in this repository

---

## Abstract

QRFS is a physical, offline, encrypted data transport and storage system that encodes arbitrary
files into printable QR code pages. It enables air-gapped transfer, archival on paper or other
durable physical media, and field data exchange in environments without digital connectivity. A
QRFS-encoded artifact is self-describing: the chunk headers carry enough metadata for full
reconstruction without any external manifest or application-level coordination. This document
specifies the three wire-format layers — `QFSP v1` (file payload), `QFSC v6` (cryptographic
envelope), and `QRC3` (chunk format) — as well as the cryptographic primitives, the FEC recovery
algorithm, and the conformance requirements for independent implementations. PDF page layout is
described as informative, non-normative context only; a conforming implementation MAY deliver
chunks in any container. This specification is the authoritative reference for building a
conforming QRFS encoder or decoder without reading any Python source code.

---

## Table of Contents

1. [Conventions and Terminology](#1-conventions-and-terminology)
2. [Format Overview](#2-format-overview)
3. [QFSP v1 — File Payload Format](#3-qfsp-v1--file-payload-format)
4. [QFSC v6 — Cryptographic Envelope](#4-qfsc-v6--cryptographic-envelope)
5. [QRC3 — Chunk Format](#5-qrc3--chunk-format)
6. [Cryptographic Primitives](#6-cryptographic-primitives)
7. [PDF Layout (Informative)](#7-pdf-layout-informative)
8. [Conformance](#8-conformance)
9. [Security Considerations](#9-security-considerations)
10. [Privacy Considerations](#10-privacy-considerations)
11. [IANA and Registry Considerations](#11-iana-and-registry-considerations)
12. [References](#12-references)
13. [Appendix A — Worked Example](#appendix-a--worked-example)
14. [Appendix B — Change Log Relative to Pre-1.0 History](#appendix-b--change-log-relative-to-pre-10-history)

---

## 1. Conventions and Terminology

### 1.1 RFC 2119 Keywords

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted
as described in RFC 2119.

### 1.2 Byte Order

All multi-byte integer fields in all QRFS wire formats are **big-endian** (network byte order)
unless explicitly stated otherwise.

#### Byte layout notation

Single-byte field:
```
 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|     field     |
+-+-+-+-+-+-+-+-+
```

Multi-byte field (e.g. 4-byte uint32):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        field (big-endian)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 1.3 Glossary

| Term | Definition |
|------|-----------|
| **Envelope** | A `QFSC v6` blob: a fully self-contained cryptographic container wrapping a `QFSP` payload. |
| **Chunk** | A `QRC3` blob: a fixed-size fragment of a `QFSC` envelope, suitable for embedding in a QR symbol. |
| **Group** | A set of consecutive data chunks sharing the same `group_index`, covered by a single set of FEC parity chunks. |
| **FEC** | Forward Error Correction. QRFS supports XOR-based and Reed-Solomon FEC at the chunk level. |
| **KDF** | Key Derivation Function. Used in password mode to derive an AES-256-GCM encryption key from a user-supplied password. |
| **QFSP** | "QRFS File-Storage Payload." The inner layer that wraps a user file with metadata. |
| **QFSC** | "QRFS File-Storage Container." The cryptographic envelope layer. |
| **QRC3** | "QR Chunk version 3." The chunk framing layer. |
| **Recipient** | An entity holding an X25519 private key, identified by a key ID in pubkey-mode envelopes. |
| **Signer** | An entity holding an Ed25519 signing private key, identified by a key ID in the signer block. |
| **AAD** | Additional Authenticated Data. Bytes authenticated by AES-GCM but not encrypted. |
| **SealedBox** | The NaCl/libsodium `crypto_box_seal` construction: anonymous ephemeral X25519 + XSalsa20-Poly1305. |
| **Parity chunk** | A chunk carrying FEC recovery data for one group of data chunks. |
| **Data chunk** | A chunk carrying a slice of the encrypted payload bytes. |
| **File ID** | A 16-byte random identifier shared by all chunks of the same encoded object. |
| **Key ID** | The first 8 bytes of SHA-256 over a public key, used for fast key lookup. |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator. |

---

## 2. Format Overview

### 2.1 The Three Layers

QRFS uses three nested layers:

```
User file
    │
    ▼
┌─────────────┐
│  QFSP v1   │  File payload: filename, MIME type, size, optional compression, raw bytes.
└─────────────┘
    │
    ▼
┌─────────────┐
│  QFSC v6   │  Cryptographic envelope: clear / password / pubkey. Optional Ed25519 signature.
└─────────────┘
    │
    ▼
┌─────────────────────────┐
│  QRC3[0] QRC3[1] … QRC3[N]  │  Chunk layer: fixed-size fragments + optional FEC parity chunks.
└─────────────────────────┘
    │
    ▼
QR symbols → printed pages or PNG images
```

**`QFSP v1`** is the _file payload format_. It wraps a single user file together with its
filename, MIME type, original size, and a compression flag. This is what the user thinks of as
"the file" once it is inside QRFS.

**`QFSC v6`** is the _cryptographic envelope_. It encrypts and authenticates a `QFSP` payload.
Three modes are defined: `clear` (unauthenticated passthrough with optional signature), `password`
(Argon2id KDF + AES-256-GCM), and `pubkey` (NaCl SealedBox + AES-256-GCM). Optional Ed25519
signing is independent of the encryption mode.

**`QRC3`** is the _chunk format_. It splits a `QFSC` envelope blob into fixed-size payload
fragments, each stamped with a common file ID, a global data index, a group index, and FEC
metadata. Parity chunks carry additional XOR or Reed-Solomon recovery data.

### 2.2 Encoding Pipeline

```
user file
    → pack_file_payload()        →  QFSP v1 blob
    → encrypt_file_payload_*()   →  QFSC v6 blob
    → make_chunks()              →  [QRC3 chunk bytes, …]
    → base45_encode(chunk)       →  Base45 text strings
    → qrcode.generate(text)      →  QR symbols
    → layout on page             →  PDF / PNG pages
```

### 2.3 Decoding Pipeline (Reverse)

```
QR scans → base45_decode()      →  QRC3 chunk bytes
         → parse_chunk()        →  Chunk structs
         → reconstruct_from_chunks()  →  QFSC v6 blob
         → decrypt_file_payload_*()   →  QFSP v1 blob
         → unpack_file_payload()      →  user file bytes + metadata
```

### 2.4 Standalone Decoding

The chunk-level metadata (file ID, index, total, group, FEC type) is **sufficient for full
reassembly**. No PDF parsing, no external manifest, and no application-layer session state is
required. This property enables future standalone decoders (JS browser, embedded C, Rust auditor)
to operate independently of the reference Python implementation.

---

## 3. QFSP v1 — File Payload Format

### 3.1 Overview

A `QFSP v1` blob wraps exactly one logical file. It is produced by the encoder before any
cryptographic processing. The decoder MUST produce the original file bytes from a valid `QFSP v1`
blob.

### 3.2 Binary Layout

```
Offset   Length   Type      Field          Description
------   ------   ----      -----          -----------
0        4        bytes     magic          ASCII "QFSP" (0x51 0x46 0x53 0x50)
4        1        uint8     version        Format version. MUST be 0x01.
5        4        uint32    metadata_len   Length of the metadata JSON, big-endian.
9        4        uint32    payload_len    Length of the file payload, big-endian.
13       N        bytes     metadata       UTF-8 JSON object (see §3.3).
13+N     M        bytes     payload        Raw file bytes, or zlib-compressed file bytes.
```

Total fixed header: **13 bytes** (4 magic + 1 version + 4 metadata_len + 4 payload_len).

The Python struct format string for the three fixed fields after the magic is `">BII"`.

### 3.3 Metadata JSON

The `metadata` field is a compact UTF-8-encoded JSON object with **no trailing whitespace** and
**no pretty-printing**. The encoder MUST produce keys in the following order, using the `','` and
`':'` separators with no extra spaces (i.e., `json.dumps(..., separators=(",", ":"))` behaviour):

```json
{"filename":"<string>","mime_type":"<string>","compressed":<bool>,"original_size":<int>}
```

| Key | Type | Description |
|-----|------|-------------|
| `filename` | string | Original filename, UTF-8 encoded. |
| `mime_type` | string | MIME type of the file (e.g. `"text/plain"`, `"application/zip"`). |
| `compressed` | boolean | `true` if the payload bytes are zlib-compressed; `false` otherwise. |
| `original_size` | integer | Size of the **original** (uncompressed) file in bytes. |

The decoder MUST parse the JSON and use `original_size` for integrity verification after
decompression if `compressed` is `true`.

### 3.4 Payload Bytes

When `compressed` is `true`, the `payload` field contains the output of
`zlib.compress(original_bytes, level=9)`. The decoder MUST call `zlib.decompress()` (or
equivalent RFC 1950 zlib inflate) to recover the original bytes.

The encoder MUST only store the compressed form if `len(compressed) < len(original)`. If
compression does not reduce size, the encoder MUST store the raw bytes and set `compressed:
false`.

### 3.5 Version Policy

The decoder MUST check that `version == 0x01`. Any other value MUST be rejected with a clear
error. No provision for `QFSP v2` or higher exists in this specification; such versions would
require a future revision of this document.

### 3.6 Byte Layout Diagram

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  'Q'(0x51)  |  'F'(0x46)  |  'S'(0x53)  |  'P'(0x50)  |  v  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         metadata_len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          payload_len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             metadata (metadata_len bytes, UTF-8 JSON)        …|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              payload (payload_len bytes)                      …|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.7 Test Vector References

The reference vectors for `QFSP v1` are in `tests/vectors/packaged/`:

| File | Input | Notes |
|------|-------|-------|
| `empty.qfsp` | `inputs/empty.bin` (0 bytes) | Edge case: zero-length file |
| `one_byte.qfsp` | `inputs/one_byte.bin` (1 byte) | Minimal non-empty file |
| `small_text.qfsp` | `inputs/small_text.txt` (633 bytes) | ASCII text, zlib-compressed |
| `utf8_emoji.qfsp` | `inputs/utf8_emoji.txt` | UTF-8 filename and content |
| `incompressible.qfsp` | `inputs/incompressible.bin` | Random bytes, stored uncompressed |
| `compressible.bin.qfsp` | `inputs/compressible.bin` | Highly compressible binary |

All files in this directory are deterministic (same input always produces identical bytes) and
are listed in `tests/vectors/manifest.json` with their SHA-256 digests.

---

## 4. QFSC v6 — Cryptographic Envelope

### 4.1 Overview

A `QFSC v6` blob wraps a `QFSP v1` payload (or any opaque byte string) with a cryptographic
envelope. Three modes are defined. In all modes, AES-256-GCM provides authenticated encryption;
the entire header (including all mode-specific fields and the optional signer block) is
authenticated as AAD. An optional Ed25519 signature covers the full blob.

### 4.2 Common Header

All `QFSC v6` blobs begin with the following 7-byte common header:

```
Offset   Length   Type      Field     Description
------   ------   ----      -----     -----------
0        4        bytes     magic     ASCII "QFSC" (0x51 0x46 0x53 0x43)
4        1        uint8     version   Format version. MUST be 0x06.
5        1        uint8     mode      0x00=clear, 0x01=password, 0x02=pubkey
6        1        uint8     flags     Bit field. Bit 0 (0x01) = FLAG_SIGNED.
```

The decoder MUST:
1. Verify `magic == b"QFSC"`.
2. Verify `version == 0x06`. A `version == 0x05` value MUST be rejected with a specific error
   (see §4.8). Any other unsupported version MUST also be rejected.
3. Read `mode` and dispatch to the appropriate mode parser (§4.4, §4.5, §4.6).

### 4.3 Flag Bits

| Bit | Mask | Name | Description |
|-----|------|------|-------------|
| 0 | 0x01 | `FLAG_SIGNED` | Ed25519 signature present (§4.7). |
| 1–7 | — | Reserved | MUST be 0. Decoders SHOULD ignore unknown bits. |

### 4.4 Clear Mode (mode = 0x00)

Clear mode stores the `QFSP` payload without encryption. A signature MAY be present.

#### Full byte layout

```
Offset   Length     Type    Field         Description
------   ------     ----    -----         -----------
0        4          bytes   magic         "QFSC"
4        1          uint8   version       6
5        1          uint8   mode          0
6        1          uint8   flags         bit 0 = FLAG_SIGNED
7        40 (cond.) bytes   signer_block  Present iff FLAG_SIGNED (see §4.7)
7 or 47  …          bytes   payload       Raw QFSP bytes (not encrypted)
end-64   64 (cond.) bytes   signature     Ed25519 signature iff FLAG_SIGNED (see §4.7)
```

Note: the payload offset is 7 if not signed, or 47 if signed (7 + 40 bytes signer block).

#### AAD

Clear mode does NOT use AES-GCM (there is no encryption), so there is no AAD. The signature, if
present, covers `header + signer_block + payload` (everything except the final 64 signature
bytes).

### 4.5 Password Mode (mode = 0x01)

Password mode derives a 32-byte AES-256-GCM key from a user-supplied password using Argon2id, then
encrypts the `QFSP` payload. The AES-GCM nonce and all header bytes (including the KDF parameter
block) are stored in the clear and authenticated as AAD.

#### Full byte layout

```
Offset   Length     Type    Field            Description
------   ------     ----    -----            -----------
0        4          bytes   magic            "QFSC"
4        1          uint8   version          6
5        1          uint8   mode             1
6        1          uint8   flags            bit 0 = FLAG_SIGNED
7        16         bytes   salt             Argon2id salt; MUST come from a CSPRNG.
23       12         bytes   nonce            AES-GCM nonce; MUST come from a CSPRNG.
35       9          bytes   kdf_block        KDF parameter block (see §4.5.1)
44       40 (cond.) bytes   signer_block     Present iff FLAG_SIGNED (see §4.7)
44 or 84 …          bytes   ciphertext+tag   AES-256-GCM output (plaintext + 16-byte GCM tag)
end-64   64 (cond.) bytes   signature        Ed25519 signature iff FLAG_SIGNED (see §4.7)
```

Note: ciphertext+tag offset is 44 if not signed, or 84 if signed (44 + 40 signer block).

#### 4.5.1 KDF Parameter Block (9 bytes)

The KDF parameter block encodes the Argon2id parameters into the envelope so any decoder can
reproduce the key derivation without out-of-band configuration. It uses the struct format
`">BIBBBB"`:

```
Offset (within block)   Length   Type    Field            Description
---------------------   ------   ----    -----            -----------
0                       1        uint8   kdf_algorithm    KDF algorithm. MUST be 0x01 (Argon2id).
1                       4        uint32  kdf_memory_kib   Memory cost in KiB (big-endian).
5                       1        uint8   kdf_time_cost    Time cost (number of iterations).
6                       1        uint8   kdf_parallelism  Degree of parallelism.
7                       1        uint8   kdf_salt_length  Salt length in bytes. MUST match the
                                                           actual salt length in the header (16).
8                       1        uint8   kdf_output_len   Output key length in bytes (32).
```

**Algorithm constants:**

| Value | Algorithm |
|-------|-----------|
| 0x01  | Argon2id  |
| 0x02–0xFF | Reserved; decoder MUST reject. |

**Valid parameter ranges** (decoders MUST validate and reject out-of-range values):

| Field | Minimum | Maximum |
|-------|---------|---------|
| `kdf_memory_kib` | 8 KiB | 4,194,304 KiB (4 GiB) |
| `kdf_time_cost` | 1 | 255 |
| `kdf_parallelism` | 1 | 255 |
| `kdf_salt_length` | 1 | 255 |
| `kdf_output_len` | 1 | 255 |

The decoder MUST use exactly the parameters embedded in the envelope, regardless of any local
profile name or default. The three built-in profiles are **non-normative recommendations** for
encoders; they carry no special meaning on the wire.

**Built-in KDF profiles (non-normative, encoder-side only):**

| Profile name | `kdf_memory_kib` | `kdf_time_cost` | `kdf_parallelism` |
|--------------|-----------------|-----------------|-------------------|
| `interactive` | 65,536 (64 MiB) | 3 | 1 |
| `default` | 262,144 (256 MiB) | 3 | 1 |
| `sensitive` | 1,048,576 (1 GiB) | 4 | 1 |

#### 4.5.2 AAD for Password Mode

The AAD passed to AES-256-GCM MUST be all bytes from offset 0 through the end of the
`signer_block` (inclusive), i.e., the entire envelope header up to but not including the
ciphertext:

- Without signature: `header[0:44]` (7 common + 16 salt + 12 nonce + 9 kdf_block = 44 bytes).
- With signature: `header[0:84]` (44 + 40 signer_block bytes = 84 bytes).

The decoder MUST pass the identical byte range as AAD to AES-GCM decrypt, otherwise decryption
will fail with an authentication error.

#### 4.5.3 Key Derivation

The AES-256-GCM key is derived as:

```
key = argon2id(
    password  = UTF-8 encoded password,
    salt      = header[7:23],          # 16 bytes from envelope
    opslimit  = kdf_time_cost,
    memlimit  = kdf_memory_kib * 1024, # in bytes
    keylen    = kdf_output_len,        # typically 32
)
```

#### 4.5.4 Password Constraints

The encoder MUST enforce a minimum password length of **14 characters** (measured in Python
`len()`, i.e. Unicode code points, not bytes). The decoder is not required to re-enforce this
constraint but SHOULD document it.

### 4.6 Pubkey Mode (mode = 0x02)

Pubkey mode uses the NaCl SealedBox construction to anonymously encrypt a random 32-byte AES-256-
GCM session key to the recipient's X25519 public key. The payload is then encrypted with that
session key. No password is needed; only the recipient's private key can decrypt.

#### Full byte layout

```
Offset   Length     Type    Field           Description
------   ------     ----    -----           -----------
0        4          bytes   magic           "QFSC"
4        1          uint8   version         6
5        1          uint8   mode            2
6        1          uint8   flags           bit 0 = FLAG_SIGNED
7        8          bytes   recipient_key_id  First 8 bytes of SHA-256(recipient_public_key)
15       2          uint16  sealed_len      Length of the sealed session key blob (big-endian).
17       12         bytes   nonce           AES-GCM nonce; MUST come from a CSPRNG.
29       40 (cond.) bytes   signer_block    Present iff FLAG_SIGNED (see §4.7)
29 or 69 sealed_len bytes   sealed          NaCl SealedBox-encrypted session key (see §4.6.1)
after    …          bytes   ciphertext+tag  AES-256-GCM output (plaintext + 16-byte GCM tag)
end-64   64 (cond.) bytes   signature       Ed25519 signature iff FLAG_SIGNED (see §4.7)
```

Note: the `sealed` blob offset is 29 if not signed, or 69 if signed (29 + 40 signer block).

#### 4.6.1 SealedBox Construction

The `sealed` blob is produced by `crypto_box_seal(session_key, recipient_pk)` (libsodium). For
a 32-byte session key and a 32-byte X25519 public key:

- The encoder generates a fresh ephemeral X25519 keypair `(eph_sk, eph_pk)` from a CSPRNG.
- `sealed = eph_pk (32 bytes) || crypto_box(session_key, nonce=H(eph_pk||recipient_pk)[:24], eph_sk, recipient_pk)`
- The inner `crypto_box` uses XSalsa20-Poly1305, producing a 48-byte output (32-byte ciphertext +
  16-byte Poly1305 MAC).
- Total `sealed_len = 32 + 48 = 80 bytes` for a 32-byte session key.

The `sealed_len` field in the header MUST be set to the actual length of the `sealed` blob (80
bytes in all current deployments of this specification).

#### 4.6.2 AAD for Pubkey Mode

The AAD passed to AES-256-GCM MUST be all bytes from offset 0 through the end of the
`signer_block` (inclusive), i.e., the entire envelope header up to but not including the
`sealed` blob:

- Without signature: `header[0:29]` (7 common + 8 key_id + 2 sealed_len + 12 nonce = 29 bytes).
- With signature: `header[0:69]` (29 + 40 signer_block bytes = 69 bytes).

#### 4.6.3 Recipient Key ID

The `recipient_key_id` is derived as:

```
recipient_key_id = SHA-256(recipient_x25519_public_key_bytes)[:8]
```

The decoder MUST verify that `recipient_key_id` matches the key ID derived from the private key
it holds before attempting decryption. If the key ID does not match, the decoder MUST return an
error ("provided private key does not match the expected recipient").

### 4.7 Signing (FLAG_SIGNED)

When bit 0 of `flags` is set, the envelope is Ed25519-signed. The signing mechanism is identical
across all three modes.

#### 4.7.1 Signer Block (40 bytes, in header)

The signer block is inserted into the header immediately after the mode-specific header fields
(before the ciphertext / payload). It contains:

```
Offset within block   Length   Type    Field          Description
-------------------   ------   ----    -----          -----------
0                     8        bytes   signer_key_id  First 8 bytes of SHA-256(verify_key_bytes)
8                     32       bytes   verify_key     Raw Ed25519 verify key (public key), 32 bytes
```

Total signer block: **40 bytes**.

The `signer_key_id` is derived as:

```
signer_key_id = SHA-256(ed25519_verify_key_bytes)[:8]
```

#### 4.7.2 Signature (64 bytes, appended at end)

When `FLAG_SIGNED` is set, a 64-byte Ed25519 signature is appended at the very end of the blob
**after** the ciphertext (or plaintext, in clear mode).

The signature covers the entire blob **excluding** the final 64 signature bytes:

```
signed_blob = magic || version || mode || flags || [mode-specific header] || [signer_block]
              || ciphertext_or_payload
signature = Ed25519.sign(signed_blob, signing_private_key)
```

#### 4.7.3 Verification Order

A decoder encountering `FLAG_SIGNED` MUST:

1. **Verify the Ed25519 signature first**, before attempting any decryption.
2. Extract the verify key from the signer block in the header.
3. Verify `signature` over `blob[:-64]` using the extracted verify key.
4. If verification fails, MUST reject the blob with a clear error ("invalid digital signature").
5. Only after successful signature verification, proceed with decryption.

This order ensures that a tampered or corrupted blob is detected before any decryption work is
performed.

### 4.8 Version Policy

`QFSC v6` is the current and only supported version in this specification.

- A decoder encountering `version == 0x05` MUST reject the blob with the specific error: "QFSC
  v5 envelopes are not supported."
- A decoder encountering any other unsupported version MUST reject with a clear error naming the
  version.
- QRFS pre-1.0 makes no migration guarantee for any version prior to v6. Starting from QRFS 1.0,
  any future version bump will be explicitly documented.

### 4.9 Mode-Specific Byte Offset Summary

The following table shows the byte offset of the start of the `ciphertext+tag` (or plaintext in
clear mode), accounting for the optional signer block:

| Mode | Not signed | Signed (FLAG_SIGNED) |
|------|-----------|---------------------|
| clear (0x00) | 7 | 47 |
| password (0x01) | 44 | 84 |
| pubkey (0x02) | 29 + sealed_len | 69 + sealed_len |

---

## 5. QRC3 — Chunk Format

### 5.1 Overview

The `QRC3` format splits a `QFSC v6` envelope blob into fixed-size fragments called _data
chunks_. Optionally, _parity chunks_ are generated for FEC recovery. All chunks belonging to the
same encoded object share the same `file_id`. Each QR code carries exactly one chunk blob,
Base45-encoded.

### 5.2 Chunk Header Layout

```
Offset   Length   Type    Field         Description
------   ------   ----    -----         -----------
0        4        bytes   magic         ASCII "QRC3" (0x51 0x52 0x43 0x33)
4        1        uint8   version       Format version. MUST be 0x03.
5        16       bytes   file_id       Random 16-byte object identifier (same for all chunks).
21       1        uint8   kind          0x00 = data, 0x01 = parity
22       1        uint8   fec_type      0x00 = none, 0x01 = XOR, 0x02 = Reed-Solomon
23       4        uint32  index         Global data chunk index (for data) or group_index (for parity)
27       4        uint32  total         Total number of DATA chunks in this object
31       2        uint16  payload_len   Length of the payload field in bytes
33       4        uint32  group_index   FEC group number (0-based)
37       2        uint16  group_size    Nominal number of data chunks per FEC group
39       2        uint16  parity_count  Number of parity chunks per group
41       2        uint16  parity_index  Which parity chunk this is within the group (see §5.4)
43       …        bytes   payload       payload_len bytes of data or parity content
```

Total fixed header: **43 bytes**.

The struct layout for the fields after `file_id` is (Python format string `">BBIIHIHH"` for
fields 21–40, plus a separate `">H"` for `parity_index`):

```
B  kind
B  fec_type
I  index
I  total
H  payload_len
I  group_index
H  group_size
H  parity_count
H  parity_index  (packed separately)
```

### 5.3 Field Semantics for Data Chunks

| Field | Value |
|-------|-------|
| `kind` | 0x00 |
| `fec_type` | 0x00 (none), 0x01 (XOR), or 0x02 (RS) — matches the parity type for this group |
| `index` | Global zero-based data chunk position (0 ≤ index < total) |
| `total` | Total number of data chunks in this object |
| `payload_len` | Actual data bytes in this chunk's payload (≤ chunk_size) |
| `group_index` | Which FEC group this chunk belongs to (= `index // group_size`; 0 if no FEC) |
| `group_size` | Nominal data chunks per FEC group (0 if FEC disabled) |
| `parity_count` | Number of parity chunks per group (0 if FEC disabled) |
| `parity_index` | SHOULD be 0 for data chunks (unused); decoders MUST ignore this field for `kind=0` |

### 5.4 Field Semantics for Parity Chunks

| Field | Value |
|-------|-------|
| `kind` | 0x01 |
| `fec_type` | 0x01 (XOR) or 0x02 (RS) |
| `index` | Set to `group_index` (not meaningful as a data index) |
| `total` | Same `total` data chunk count as the data chunks in this object |
| `group_index` | Which FEC group this parity chunk covers |
| `group_size` | Nominal data chunks per FEC group |
| `parity_count` | Number of parity chunks per group |
| `parity_index` | **XOR**: MUST be 0 (only one parity per group). **RS**: 0-based index within [0, parity_count-1]. |

#### `parity_index` semantics

- For XOR FEC: `parity_index = 0` always (there is exactly one XOR parity chunk per group).
- For Reed-Solomon FEC: `parity_index ∈ [0, parity_count - 1]`, uniquely identifying each RS
  parity chunk within the group.
- For data chunks: `parity_index` is unused and MUST be written as 0; decoders MUST ignore it.

### 5.5 `total` Field Invariant

The `total` field always means the **number of data chunks**, not the total count of all QR
codes (which includes parity). All chunks belonging to the same object MUST carry the same
`total` value. A decoder finding inconsistent `total` values across chunks MUST reject the set.

### 5.6 FEC Type Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | none | No FEC. No parity chunks are generated. |
| 0x01 | XOR | XOR FEC: 1 parity chunk per group. |
| 0x02 | rs | Reed-Solomon FEC: 1–4 parity chunks per group. |

### 5.7 Parity Payload Internal Structure

Both XOR and RS parity chunks use the same internal payload format. The payload field begins with
a length-prefix metadata section followed by the parity bytes:

```
Offset within payload   Length   Type    Field               Description
---------------------   ------   ----    -----               -----------
0                       2        uint16  meta_count          Number of data chunks in the group
2                       2×n      uint16  lengths[meta_count] Original payload_len for each data chunk
2+2*n                   …        bytes   parity_bytes        XOR or RS parity data (chunk_size bytes)
```

The `meta_count` field records how many data chunks are in this FEC group. For the last group,
this may be smaller than `group_size` if the total number of data chunks is not evenly divisible
by `group_size`. The `lengths` array records the original `payload_len` of each data chunk in the
group, enabling the decoder to strip zero-padding after XOR or RS recovery.

The `parity_bytes` are padded to `chunk_size` bytes (the nominal maximum payload size for data
chunks in this object).

### 5.8 FEC Group Layout

Data chunks are assigned to groups as follows:

```
group_index = index // group_size   (if FEC enabled)
group_index = 0                     (if FEC disabled)
```

Within a group, data chunks have consecutive `index` values. The last group may be partial (fewer
than `group_size` data chunks).

Allowed values for `group_size`: 0 (disabled), 2, 3, 4, 5, 6, 8.
Allowed values for `parity_count` (RS): 1, 2, 3, or 4 (must be < group_size).
XOR supports only `parity_count = 1`.

### 5.9 Version Policy

The decoder MUST verify `version == 0x03`. Any other value MUST be rejected. The decoder MUST
verify `magic == b"QRC3"`. Any other magic MUST be rejected. Chunk formats `QRC1` and `QRC2` are
not supported and MUST be rejected.

### 5.10 Reassembly Algorithm (Informative Pseudocode)

The following pseudocode describes the reassembly process. It is informative; the normative
behaviour is that of `qrfs/core/chunker.py:reconstruct_from_chunks()`.

```python
# Informative reassembly pseudocode

def reassemble(raw_chunks: list[bytes]) -> bytes:
    chunks = [parse_chunk(r) for r in raw_chunks]

    # All chunks must share the same file_id and total.
    assert len({c.file_id for c in chunks}) == 1, "mismatched file_id"
    assert len({c.total for c in chunks}) == 1, "inconsistent total"
    total_data = chunks[0].total

    # Determine the maximum chunk payload size for FEC padding.
    chunk_size = max(
        (len(c.payload) for c in chunks if c.kind == KIND_DATA),
        default=0
    )
    for p in (c for c in chunks if c.kind == KIND_PARITY):
        lengths, parity_blob = decode_lengths_prefix(p.payload)
        chunk_size = max(chunk_size, len(parity_blob))

    # Group all chunks by group_index.
    groups: dict[int, list[Chunk]] = {}
    for c in chunks:
        groups.setdefault(c.group_index, []).append(c)

    # Recover data for each group.
    by_index: dict[int, bytes] = {}
    for group_chunks in groups.values():
        parity = next((c for c in group_chunks if c.kind == KIND_PARITY), None)
        if parity is None or parity.fec_type == FEC_NONE:
            # No FEC: collect data chunks directly.
            recovered = {c.index: c.payload for c in group_chunks if c.kind == KIND_DATA}
        elif parity.fec_type == FEC_XOR:
            recovered = recover_group_xor(group_chunks, total_data, chunk_size)
        elif parity.fec_type == FEC_RS:
            recovered = recover_group_rs(group_chunks, total_data, chunk_size)
        by_index.update(recovered)

    # Verify all data chunks are accounted for.
    missing = [i for i in range(total_data) if i not in by_index]
    if missing:
        raise ValueError(f"Missing chunks: {missing}")

    # Concatenate data chunks in index order.
    return b"".join(by_index[i] for i in range(total_data))


def decode_lengths_prefix(parity_payload: bytes) -> tuple[list[int], bytes]:
    """Decode the meta_count + lengths[] prefix from a parity payload."""
    meta_count = struct.unpack(">H", parity_payload[:2])[0]
    lengths = [
        struct.unpack(">H", parity_payload[2 + i*2 : 4 + i*2])[0]
        for i in range(meta_count)
    ]
    parity_data = parity_payload[2 + 2*meta_count:]
    return lengths, parity_data
```

---

## 6. Cryptographic Primitives

### 6.1 Argon2id (Password Mode KDF)

QRFS uses **Argon2id** as defined in RFC 9106. The parameters are carried explicitly in the
envelope header (§4.5.1). Implementations MUST use the parameters from the envelope, not any
hard-coded default.

- **Algorithm**: Argon2id (hybrid of Argon2i and Argon2d, RFC 9106 §4).
- **Output**: Variable length, stored in `kdf_output_length` (currently always 32 bytes).
- **Salt**: Variable length, stored in `kdf_salt_length` (currently always 16 bytes), drawn from
  a CSPRNG at encryption time.
- **Password encoding**: The password string is encoded as UTF-8 before passing to Argon2id.
- **Reference**: RFC 9106 §3–4; libsodium `crypto_pwhash_ALG_ARGON2ID13`.

### 6.2 AES-256-GCM (Authenticated Encryption)

QRFS uses **AES-256-GCM** as specified in NIST SP 800-38D.

- **Key size**: 256 bits (32 bytes).
- **Nonce size**: 96 bits (12 bytes). The nonce MUST be drawn from a CSPRNG for each encryption.
  Nonce reuse with the same key is a catastrophic security failure.
- **Tag size**: 128 bits (16 bytes, appended to the ciphertext).
- **AAD**: The complete envelope header up to and including the optional signer block (see
  §4.5.2 and §4.6.2 for precise byte ranges). The decoder MUST reconstruct the identical AAD
  bytes from the header to verify the authentication tag.
- **Reference**: NIST SP 800-38D; Python `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

### 6.3 X25519 + NaCl SealedBox (Pubkey Mode Key Exchange)

QRFS uses the NaCl SealedBox construction (libsodium `crypto_box_seal`) for key exchange in
pubkey mode.

- **Curve**: X25519 (Diffie-Hellman over Curve25519), RFC 7748.
- **Inner cipher**: XSalsa20-Poly1305 (`crypto_box`).
- **Ephemeral key**: A fresh X25519 keypair MUST be generated from a CSPRNG for each encryption.
  The ephemeral public key is prepended to the sealed output.
- **Anonymity**: SealedBox does not authenticate the sender; only the recipient's public key is
  used in key agreement.
- **Reference**: RFC 7748; libsodium documentation for `crypto_box_seal`.

### 6.4 Ed25519 (Signatures)

QRFS uses **Ed25519** as specified in RFC 8032 for optional payload signing.

- **Key size**: 32-byte private seed, 32-byte public verify key.
- **Signature size**: 64 bytes.
- **Signed data**: The full blob excluding the final 64 signature bytes (§4.7.2).
- **Reference**: RFC 8032; PyNaCl `nacl.signing.SigningKey`.

### 6.5 Random Sources

All of the following MUST be drawn from a CSPRNG (i.e., `os.urandom()` on POSIX systems, or an
equivalent OS-level secure random source):

- Argon2id salt (16 bytes).
- AES-GCM nonce (12 bytes).
- AES-256-GCM session key in pubkey mode (32 bytes).
- Ephemeral X25519 keypair in SealedBox.
- `file_id` in QRC3 chunks (16 bytes).

Test-only override parameters (`_salt`, `_nonce`, `_file_id`) exist in the reference
implementation for deterministic vector generation. These MUST NOT be used in production.

### 6.6 Key IDs

Key IDs are used for fast key lookup without storing full public keys in compact fields.

**Encryption key ID** (used in pubkey mode `recipient_key_id`):
```
key_id = SHA-256(x25519_public_key_bytes)[:8]
```

**Signing key ID** (used in signer block `signer_key_id`):
```
signer_key_id = SHA-256(ed25519_verify_key_bytes)[:8]
```

Key IDs are 8 bytes (64 bits). Collision probability is negligible for the expected number of
keys in any realistic deployment, but implementations MUST NOT rely on key IDs alone for
security-critical decisions; the full public key is always present in the signer block.

### 6.7 Base45 Carrier Encoding

Chunk blobs are Base45-encoded before being placed into a QR symbol. QRFS uses the Base45
alphabet defined in RFC 9285:

```
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:
```

The decoder MUST Base45-decode the QR symbol payload before calling `parse_chunk()`. Base45 is
not part of the `QFSP`, `QFSC`, or `QRC3` wire formats; it is the carrier encoding at the QR
symbol level.

---

## 7. PDF Layout (Informative)

**This section is informative and non-normative.** A conforming QRFS implementation MAY deliver
chunks in any container: PDF, individual PNG images, a video stream, ESC/POS thermal printer
output, etc. The chunk wire format (§5) is self-describing, and chunk-level metadata is
sufficient for full reassembly — no PDF parsing is required.

The reference Python implementation's PDF layout:

- Page size: A4.
- Grid: 5 columns × 6 rows = 30 QR codes per page.
- Each QR symbol encodes one `QRC3` chunk blob, Base45-encoded, in QR alphanumeric mode.
- Footer label per QR:
  - Data chunks: `D{index+1}/{total}` (e.g. `D5/12`).
  - Parity chunks: `P{parity_index+1}/{parity_count} G{group_index+1}` (e.g. `P1/2 G3`).
- The encoder applies a stride-based interleaving of chunk order within each page to spread
  logically adjacent chunks apart. This is a layout optimisation and is not part of the wire
  format.

Future encoders (e.g. a JavaScript browser encoder, an embedded C encoder) SHOULD produce QR
symbols with the same content (Base45-encoded `QRC3` blobs) but MAY use any page layout.

---

## 8. Conformance

### 8.1 Conformance Vectors

The canonical conformance test vectors are located in `tests/vectors/` in this repository. The
manifest file `tests/vectors/manifest.json` lists every vector file with its SHA-256 digest and
a `deterministic` flag.

A conforming implementation:

- **MUST** produce bytes byte-identical to the recorded SHA-256 for every vector with
  `"deterministic": true` (QFSP payloads, clear-mode envelopes, password envelopes with fixed
  salt/nonce, QRC3 chunks with fixed `file_id`).
- **MUST** successfully decrypt / decode vectors with `"deterministic": false` (pubkey envelopes,
  where the SealedBox ephemeral key is random per encryption). These vectors are tested by
  decrypting and comparing the plaintext, not by byte-comparing the ciphertext.

### 8.2 Conformance Levels

| Level | Name | Requirements |
|-------|------|-------------|
| 1 | **Reader** | Can decode, decrypt, and unpack any valid QRFS artifact produced by a Level 2 or 3 writer. |
| 2 | **Writer** | Can produce valid QRFS artifacts that any Level 1 reader accepts. |
| 3 | **Round-trip** | Both Level 1 and Level 2, plus byte-identity with deterministic vectors. |

The Python reference implementation (`flyingsurveyor/qrfs`) is **Level 3**.

A future implementation (e.g. a JavaScript browser decoder) targeting only decryption MUST
self-declare **Level 1**. An implementation targeting both encoding and decoding MUST self-declare
**Level 2** or **Level 3**, and run the conformance vectors to verify.

### 8.3 Mandatory Rejection Conditions

A conforming decoder MUST reject (with a clear human-readable error message) any artifact that
violates the following:

| Condition | Required error |
|-----------|---------------|
| `QFSP` magic ≠ `"QFSP"` | "Invalid payload magic." |
| `QFSP` version ≠ 1 | "Unsupported payload version: N" |
| `QFSC` magic ≠ `"QFSC"` | "Invalid transport blob." |
| `QFSC` version = 5 | "QFSC v5 envelopes are not supported." |
| `QFSC` version ≠ 6 (other) | "Unsupported cryptographic version: N" |
| `QFSC` unknown mode | "Unsupported encryption mode: N" |
| AES-GCM tag verification failure | "Wrong password or corrupted data." |
| Ed25519 signature verification failure | "Digital signature non valida." |
| `QRC3` magic ≠ `"QRC3"` | "QR payload has an invalid chunk magic header." |
| `QRC3` version ≠ 3 | "Unsupported chunk version: N" |
| `QRC3` chunks with mismatched `file_id` | "Chunks belong to different files." |
| `QRC3` chunks with inconsistent `total` | "Inconsistent total chunk count." |
| Argon2id parameters out of range | (parameter-specific range error) |

---

## 9. Security Considerations

### 9.1 Threat Model

QRFS is designed to protect against:

- **Passive observation** of stored or printed envelopes (confidentiality via AES-256-GCM in
  password or pubkey mode).
- **Integrity tampering** of the envelope or chunks (detected by AES-GCM authentication tag and
  optional Ed25519 signature).
- **Recipient impersonation** in pubkey mode (only the holder of the X25519 private key can
  decrypt).
- **Offline brute-force of passwords** (mitigated by the Argon2id KDF with memory-hardness).

### 9.2 What QRFS Does NOT Protect Against

- **Side-channel attacks** during decoding (timing attacks on AES, cache attacks on Argon2id).
- **RAM scraping** post-decryption (plaintext is in memory after decryption; QRFS makes no
  attempt to wipe keys or plaintext from memory).
- **Weak passwords**: Argon2id raises the cost of brute-force but cannot compensate for a
  password with low entropy. The minimum 14-character requirement is a practical lower bound,
  not a security guarantee.
- **QR substitution attacks**: If an attacker can replace printed QR codes, they could substitute
  malicious chunks. This is mitigated only if signatures are used (FLAG_SIGNED).
- **Clear mode eavesdropping**: In clear mode, the payload is not encrypted. Anyone with access
  to the QR codes can read the data.

### 9.3 Password Strength

The encoder enforces a minimum password length of **14 characters**. Implementations SHOULD
encourage longer, randomly generated passwords (e.g. Diceware passphrases of ≥6 words). The
`default` KDF profile (256 MiB, 3 iterations) is the RECOMMENDED baseline. The `sensitive`
profile (1 GiB, 4 iterations) SHOULD be used for long-term archival where decoding latency is
acceptable.

### 9.4 KDF Profile Selection Trade-offs

Higher memory and time cost parameters make offline dictionary attacks proportionally more
expensive, at the cost of longer decryption time. The `interactive` profile (64 MiB) is suitable
for use cases where decoding must be fast and the password is strong. The `default` profile
(256 MiB) balances security and usability. The `sensitive` profile (1 GiB) is for high-security,
low-frequency use.

### 9.5 Forward Secrecy

Pubkey mode does **NOT** provide forward secrecy. The recipient's long-term X25519 private key is
used directly. If that key is compromised at any point in the future, all past envelopes
encrypted to that key can be decrypted. Implementations SHOULD document this clearly to users.
For high-sensitivity use cases, users SHOULD rotate recipient keypairs periodically and re-encrypt
archives.

### 9.6 Replay Protection

QRFS does not include timestamps or sequence numbers in its wire formats. Envelopes and chunks do
not provide anti-replay guarantees. Implementations layering QRFS over a transport protocol
(e.g. a messaging system) SHOULD add their own anti-replay mechanism if needed.

### 9.7 AAD Binding

The AAD used in AES-GCM is a critical security invariant. It binds the ciphertext to the
specific envelope header (mode, flags, KDF parameters, key ID, nonce, signer block). An attacker
cannot move a ciphertext from one envelope context to another without invalidating the
authentication tag.

Re-implementers MUST take care to pass **exactly** the bytes specified in §4.5.2 and §4.6.2 as
AAD. Any deviation (including off-by-one errors in the byte range) will cause legitimate
decryptions to fail with an authentication error, and may open security vulnerabilities if the
deviation is in the wrong direction (including fewer bytes than specified).

---

## 10. Privacy Considerations

- **Filename and MIME type** are stored in cleartext inside `QFSP v1`. In `password` and
  `pubkey` modes they are encrypted together with the file content (the entire `QFSP` blob is the
  plaintext). In `clear` mode they are visible to anyone with access to the QR codes.
- **File size** leaks via the total envelope length, even in encrypted modes. An adversary
  observing the QR codes can estimate the original file size from the number of data chunks and
  the chunk size. Padding to hide file size is **NOT** in scope for v1.0 and is reserved for
  future versions.
- **Recipient identity** in pubkey mode: the 8-byte `recipient_key_id` in the header is
  observable in cleartext. An adversary who has catalogued public keys can use this to infer the
  intended recipient. Implementations targeting high anonymity SHOULD document this limitation.
- **Signer identity**: the full 32-byte Ed25519 verify key is embedded in the signer block and is
  observable in cleartext in all modes.

---

## 11. IANA and Registry Considerations

QRFS does not currently request any IANA registrations.

Future versions of the specification MAY request registration of:

- A media type `application/vnd.qrfs.envelope` for `.qfsc` files.
- A media type `application/vnd.qrfs.payload` for `.qfsp` files.

---

## 12. References

### 12.1 Normative References

| Reference | Title |
|-----------|-------|
| RFC 2119 | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. |
| RFC 9106 | Biryukov, A. et al., "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106, September 2021. |
| NIST SP 800-38D | Dworkin, M., "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", NIST Special Publication 800-38D, November 2007. |
| RFC 7748 | Langley, A., Hamburg, M., Turner, S., "Elliptic Curves for Security", RFC 7748, January 2016. |
| RFC 8032 | Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. |

### 12.2 Informative References

| Reference | Title |
|-----------|-------|
| ISO/IEC 18004 | "Information technology — Automatic identification and data capture techniques — QR Code bar code symbology specification", 3rd edition, 2015. |
| RFC 9285 | Fältström, P., "The Base45 Data Encoding", RFC 9285, August 2022. |
| QRFS README | `README.md` in this repository. User-facing overview. |
| QRFS test vectors README | `tests/vectors/README.md` in this repository. Conformance vector specification and fixture values. |
| QRFS FORMAT.md | `docs/FORMAT.md` in this repository. Implementation notes for contributors. |

---

## Appendix A — Worked Example

This appendix traces the encoding of `tests/vectors/inputs/small_text.txt` (633 bytes of ASCII
text) through all three layers of the QRFS format, using the fixed test vector fixtures. All byte
offsets and values have been verified against the reference implementation output in
`tests/vectors/`.

### A.1 Input File

```
File:        tests/vectors/inputs/small_text.txt
Size:        633 bytes
MIME type:   text/plain
```

### A.2 QFSP v1 — Hex Dump (first 64 bytes)

Source: `tests/vectors/packaged/small_text.qfsp`

```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
00      51 46 53 50  01  00 00 00 5c  00 00 01 82        QFSP.  ...\ ...
        ^^^^^^^^^^^  ^^  ^^^^^^^^^^^ ^^^^^^^^^^^
        magic        v1  meta_len=92 payload_len=386

0d      7b 22 66 69 6c 65 6e 61 6d 65 22 3a 22 73 6d 61  {"filename":"sma
1d      6c 6c 5f 74 65 78 74 2e 74 78 74 22 2c 22 6d 69  ll_text.txt","mi
2d      6d 65 5f 74 79 70 65 22 3a 22 74 65 78 74 2f 70  me_type":"text/p
3d      6c 61 69 6e 22 2c 22 63 6f 6d 70 72 65 73 73 65  lain","compresse
```

#### Field annotation:
- **Offset 0–3**: `51 46 53 50` = "QFSP" (magic).
- **Offset 4**: `01` = version 1.
- **Offset 5–8**: `00 00 00 5c` = 92 (metadata JSON length).
- **Offset 9–12**: `00 00 01 82` = 386 (zlib-compressed payload length).
- **Offset 13–104**: 92 bytes of JSON metadata:
  `{"filename":"small_text.txt","mime_type":"text/plain","compressed":true,"original_size":633}`
- **Offset 105–490**: 386 bytes of zlib-compressed file content.

Note: the payload is zlib-compressed (633 bytes → 386 bytes; `compressed: true`).

### A.3 QFSC v6 Clear Mode — Hex Dump (first 32 bytes)

Source: `tests/vectors/envelopes/clear/small_text.qfsc`

```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
00      51 46 53 43  06  00  00                          QFSC.  ..
        ^^^^^^^^^^^  ^^  ^^  ^^
        magic        v6  clr no-sign
07      51 46 53 50 01 00 00 00 5c 00 00 01 82 ...       QFSP...  (payload starts)
```

#### Field annotation:
- **Offset 0–3**: `51 46 53 43` = "QFSC" (magic).
- **Offset 4**: `06` = version 6.
- **Offset 5**: `00` = mode 0 (clear).
- **Offset 6**: `00` = flags (no signature).
- **Offset 7+**: The raw QFSP blob begins immediately (no encryption).

Total envelope overhead in clear unsigned mode: **7 bytes**.

### A.4 QFSC v6 Password Mode (default profile) — Hex Dump (first 64 bytes)

Source: `tests/vectors/envelopes/password_default/small_text.qfsc`  
Fixtures: salt = `0123456789abcdef0123456789abcdef`, nonce = `deadbeefcafebabedeadbeef`.

```
Offset  Hex                                              Notes
------  -----------------------------------------------  -----
00      51 46 53 43  06  01  00                          magic, v6, password, no-sign
07      01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef  salt (16 bytes)
17      de ad be ef ca fe ba be de ad be ef               nonce (12 bytes)
23      01  00 04 00 00  03  01  10  20                   KDF block:
        ^^  ^^^^^^^^^^^  ^^  ^^  ^^  ^^
        Argon2id  262144KiB  t=3  p=1  salt=16  out=32
2c      ...                                               ciphertext+GCM tag
```

#### KDF block detail:
- **Offset 35** (`0x23`): `01` = kdf_algorithm = Argon2id.
- **Offset 36–39** (`0x24`–`0x27`): `00 04 00 00` = 262,144 KiB = 256 MiB (`default` profile).
- **Offset 40** (`0x28`): `03` = kdf_time_cost = 3.
- **Offset 41** (`0x29`): `01` = kdf_parallelism = 1.
- **Offset 42** (`0x2a`): `10` = kdf_salt_length = 16.
- **Offset 43** (`0x2b`): `20` = kdf_output_length = 32.

Total header before ciphertext: **44 bytes** (7 common + 16 salt + 12 nonce + 9 KDF block).

### A.5 QRC3 Chunk — Hex Dump (first 64 bytes, chunk 000)

Source: `tests/vectors/chunks/small_text/000.qrc`  
Fixture: `file_id = 00112233445566778899aabbccddeeff`, `chunk_size = 100`, no FEC.

```
Offset  Hex                                              Notes
------  -----------------------------------------------  -----
00      51 52 43 33  03                                  magic "QRC3", version 3
05      00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  file_id (16 bytes)
15      00                                               kind=0 (data)
16      00                                               fec_type=0 (none)
17      00 00 00 00                                      index=0
1b      00 00 00 05                                      total=5 (5 data chunks)
1f      00 64                                            payload_len=100
21      00 00 00 00                                      group_index=0
25      00 00                                            group_size=0 (FEC disabled)
27      00 00                                            parity_count=0
29      00 00                                            parity_index=0
2b      51 46 53 43 06 00 00 51 46 53 50 01 ...          payload: first 100 bytes of QFSC blob
```

#### Field annotation:
- Total header: 43 bytes (offset 0x00 through 0x2a inclusive).
- Payload starts at offset 43 (0x2b).
- This is the first of 5 data chunks covering the full `small_text.qfsc` blob in clear mode.
- With `chunk_size=100` and no FEC, the QFSC blob is split into exactly 5 sequential 100-byte
  payload slices (the last chunk may be shorter).

---

## Appendix B — Change Log Relative to Pre-1.0 History

**QFSC v5** was the previous cryptographic envelope version. It was replaced by QFSC v6 in pre-
1.0 development to add explicit KDF parameter storage in the envelope header (Argon2id parameters
are now self-describing). No backward compatibility is provided for QFSC v5.

**QRC1 and QRC2** were earlier chunk format versions. They were replaced by QRC3 in pre-1.0
development to fix `parity_index` semantics (in prior versions, RS parity chunks incorrectly
reused `group_index` as the parity index, making multi-parity RS reconstruction ambiguous). No
backward compatibility is provided for QRC1 or QRC2.

**No backward compatibility** is provided for any pre-1.0 version of any format layer. Starting
from QRFS 1.0, any breaking change to `QFSP v1`, `QFSC v6`, or `QRC3` will be documented as a
new version with an incremented version number, and the relevant section of this specification
will be updated accordingly.
