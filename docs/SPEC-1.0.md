# QRFS Format Specification — Version 1.0

| Field               | Value                                                             |
|---------------------|-------------------------------------------------------------------|
| **Status**          | Draft (becomes "Stable" upon QRFS 1.0 release)                  |
| **Editors**         | QRFS project maintainers (flyingsurveyor)                        |
| **Date**            | 2026-05-09                                                        |
| **Reference impl.** | `flyingsurveyor/qrfs` Python package (this repository)           |
| **Test vectors**    | `tests/vectors/` in this repository                              |

---

## Abstract

QRFS (QR Filesystem) is a physical, offline data transport and archival system that encodes
encrypted files into printable QR code pages. It is designed for air-gapped, hostile,
intermittent, or infrastructure-poor environments where digital channels are unavailable or
untrusted. A QRFS-encoded file can be printed, stored physically, and later reconstructed by
scanning the QR codes — even without any network access or external software repositories.

This document specifies the three wire-format layers that constitute a QRFS artifact:
**`QFSP v1`** (file payload format), **`QFSC v6`** (cryptographic envelope), and **`QRC3`**
(chunk format with optional forward-error correction). It is intended for implementers who wish
to build conforming QRFS encoders or decoders — in any language, on any platform — without
reading the Python reference implementation. The document also covers the cryptographic
primitives, key derivation parameters, conformance requirements, and security considerations.

PDF page layout (how QR symbols are arranged on a printed page) is described in §9 as
**informative only**. A conforming implementation is not required to use PDF or any particular
layout; the chunk-level metadata in `QRC3` is sufficient for complete reassembly.

---

## Table of Contents

1. [Conventions and Terminology](#1-conventions-and-terminology)
2. [Format Overview](#2-format-overview)
3. [QFSP v1 — File Payload Format](#3-qfsp-v1--file-payload-format)
4. [QFSC v6 — Cryptographic Envelope](#4-qfsc-v6--cryptographic-envelope)
5. [QRC3 — Chunk Format](#5-qrc3--chunk-format)
6. [FEC Layer](#6-fec-layer)
7. [Base45 Carrier Encoding](#7-base45-carrier-encoding)
8. [Cryptographic Primitives](#8-cryptographic-primitives)
9. [PDF Layout (Informative)](#9-pdf-layout-informative)
10. [Conformance](#10-conformance)
11. [Security Considerations](#11-security-considerations)
12. [Privacy Considerations](#12-privacy-considerations)
13. [IANA and Registry Considerations](#13-iana-and-registry-considerations)
14. [References](#14-references)
15. [Appendix A — Worked Example](#appendix-a--worked-example)
16. [Appendix B — Pre-1.0 Change Log](#appendix-b--pre-10-change-log)

---

## 1. Conventions and Terminology

### 1.1 RFC 2119 Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[RFC 2119].

### 1.2 Byte Order

All multi-byte integer fields in this specification are **big-endian** (network byte order)
unless explicitly stated otherwise. The most significant byte is transmitted and stored first.

For example, the 32-bit unsigned integer value `5` is encoded as the four bytes `00 00 00 05`.

Byte layouts in this document use the following notation in tables:

```
Offset | Length | Type    | Field        | Description
-------|--------|---------|--------------|---------------------------
0      | 4      | bytes   | magic        | Fixed ASCII identifier
4      | 1      | uint8   | version      | Format version number
5      | 4      | uint32  | field_name   | Big-endian unsigned 32-bit
```

Types used in this document:

| Type   | Size    | Description                                     |
|--------|---------|-------------------------------------------------|
| bytes  | varies  | Raw octet string                                |
| uint8  | 1 byte  | Unsigned 8-bit integer                          |
| uint16 | 2 bytes | Unsigned 16-bit integer, big-endian             |
| uint32 | 4 bytes | Unsigned 32-bit integer, big-endian             |

### 1.3 Glossary

| Term            | Definition                                                                     |
|-----------------|--------------------------------------------------------------------------------|
| **Artifact**    | A complete QRFS-encoded file: a set of QR images (or a PDF) that encodes one input file. |
| **Chunk**       | A single `QRC3` binary blob, encoded into one QR symbol.                       |
| **CSPRNG**      | Cryptographically Secure Pseudo-Random Number Generator.                       |
| **Encoder**     | An implementation that produces QRFS artifacts from input files.               |
| **Decoder**     | An implementation that reconstructs input files from QRFS artifacts.           |
| **Envelope**    | A `QFSC v6` blob wrapping a `QFSP` payload.                                   |
| **FEC**         | Forward Error Correction — parity data that enables recovery of missing chunks. |
| **File ID**     | A 16-byte random identifier shared by all chunks of the same encoded file.     |
| **Group**       | A set of data chunks that share a single FEC parity set.                       |
| **KDF**         | Key Derivation Function.                                                       |
| **Payload**     | The `QFSP v1` blob (packed user file + metadata) inside the QFSC envelope.    |
| **Parity chunk**| A `QRC3` chunk carrying FEC recovery data, not user data.                     |
| **Recipient**   | The holder of the X25519 private key that can decrypt a pubkey-mode envelope. |
| **Sealed box**  | NaCl/libsodium anonymous sealed box: X25519 key exchange + XSalsa20-Poly1305. |
| **Signer**      | The holder of the Ed25519 signing key that produced the optional signature.    |

---

## 2. Format Overview

A QRFS artifact is produced through a three-layer pipeline:

```
User file
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  QFSP v1  (File Payload Format)                      │
│  Wraps the file with filename, MIME type, size,      │
│  and optional zlib compression.                      │
└──────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  QFSC v6  (Cryptographic Envelope)                   │
│  Encrypts/authenticates the QFSP payload.            │
│  Three modes: clear, password, pubkey.               │
│  Optional Ed25519 digital signature.                 │
└──────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  QRC3  (Chunk Format, repeated N times)              │
│  Splits the QFSC envelope into fixed-size chunks     │
│  with optional XOR or Reed-Solomon FEC parity.       │
└──────────────────────────────────────────────────────┘
   │
   ▼  (Base45 encode each chunk)
   │
   ▼  (Encode each Base45 string into a QR symbol)
   │
   ▼
QR images → Printable artifact (PDF or PNGs)
```

The decoding pipeline is the exact reverse:

```
QR scans → QRC3 chunks → QFSC envelope → QFSP payload → User file
```

### 2.1 Layer Responsibilities

| Layer    | Version | Responsibility                                                          |
|----------|---------|-------------------------------------------------------------------------|
| `QFSP`   | v1      | Packages user file with filename, MIME type, size, compression flag.   |
| `QFSC`   | v6      | Encrypts, authenticates, and optionally signs the QFSP payload.        |
| `QRC3`   | v3      | Splits the QFSC blob into indexed chunks; adds optional FEC parity.    |

### 2.2 Version Policy

- `QFSC v5` and earlier MUST be rejected by decoders with a clear error message.
- `QRC1`, `QRC2`, and earlier chunk formats MUST be rejected by decoders.
- QRFS pre-1.0 makes no migration guarantee. QRFS 1.0 onward commits to documenting any
  future format bump explicitly, with migration guidance.

---

## 3. QFSP v1 — File Payload Format

The `QFSP v1` format packages a single user file with metadata into a self-describing binary
blob. This blob is the input to the cryptographic layer (`QFSC`).

### 3.1 Magic and Version

The format begins with the 4-byte ASCII magic string `QFSP` followed by a version byte.

```
Offset 0:  51 46 53 50  ("QFSP")
Offset 4:  01           (version = 1)
```

### 3.2 Binary Layout

```
Offset | Length      | Type   | Field        | Description
-------|-------------|--------|--------------|-----------------------------------
0      | 4           | bytes  | magic        | ASCII "QFSP"
4      | 1           | uint8  | version      | Must be 1
5      | 4           | uint32 | metadata_len | Length of the metadata JSON in bytes
9      | 4           | uint32 | payload_len  | Length of the (possibly compressed) file data
13     | metadata_len| bytes  | metadata     | UTF-8 encoded JSON object (see §3.3)
13+ML  | payload_len | bytes  | payload      | Raw or zlib-compressed file bytes
```

Where `ML` = `metadata_len`.

Total header size: **13 bytes** (magic + version + metadata_len + payload_len).

### 3.3 Metadata JSON

The `metadata` field is a UTF-8 encoded JSON object with no trailing whitespace (compact form,
`separators=(",", ":")`). It MUST contain exactly the following keys in the following order:

| Key             | Type    | Description                                              |
|-----------------|---------|----------------------------------------------------------|
| `filename`      | string  | Original filename, UTF-8, no path component.            |
| `mime_type`     | string  | MIME type of the original file (e.g. `"text/plain"`).   |
| `compressed`    | boolean | `true` if `payload` is zlib-compressed; `false` if raw. |
| `original_size` | integer | Original (uncompressed) file size in bytes.             |

The encoder MUST encode the metadata using Python's `json.dumps(..., separators=(",", ":"))` or
equivalent — no spaces after separators, no trailing newline.

### 3.4 Compression

The encoder SHOULD attempt zlib compression (level 9) on the file bytes. If the compressed
form is strictly smaller than the uncompressed form, the encoder MUST store the compressed
form and set `compressed` to `true`. Otherwise, the encoder MUST store the raw bytes and
set `compressed` to `false`.

The decoder MUST decompress the payload with zlib if `compressed` is `true`.

The zlib data stream uses RFC 1950 format (2-byte header + deflate data + 4-byte Adler-32
checksum). The magic bytes in the test vectors (`78 DA`) confirm zlib default compression
level 9.

### 3.5 Decoding QFSP

A conforming decoder MUST:

1. Verify that `magic == b"QFSP"`. If not, reject with a clear error.
2. Verify that `version == 1`. If not, reject with a clear error.
3. Read `metadata_len` and `payload_len` as big-endian unsigned 32-bit integers.
4. Read exactly `metadata_len` bytes and parse as UTF-8 JSON.
5. Read exactly `payload_len` bytes.
6. If `metadata["compressed"]` is `true`, decompress with zlib.
7. Verify that the decompressed length equals `metadata["original_size"]`.

### 3.6 Test Vectors

Reference vectors are in `tests/vectors/packaged/`. All six inputs are represented:
`empty.qfsp`, `one_byte.qfsp`, `small_text.qfsp`, `utf8_emoji.qfsp`,
`incompressible.qfsp`, `compressible.qfsp`. All are `deterministic: true` in the manifest.

See Appendix A for an annotated hex dump of `small_text.qfsp`.

---

## 4. QFSC v6 — Cryptographic Envelope

The `QFSC v6` format wraps a `QFSP` payload with cryptographic protection. Three encryption
modes are defined. All modes share a common header prefix and support an optional Ed25519
digital signature.

### 4.1 Common Header Prefix

All `QFSC v6` blobs begin with:

```
Offset | Length | Type  | Field   | Description
-------|--------|-------|---------|----------------------------------------
0      | 4      | bytes | magic   | ASCII "QFSC"
4      | 1      | uint8 | version | Must be 6
5      | 1      | uint8 | mode    | 0=clear, 1=password, 2=pubkey
6      | 1      | uint8 | flags   | Bitmask; see §4.2
```

### 4.2 Flags

| Bit  | Mask   | Name        | Meaning                                       |
|------|--------|-------------|-----------------------------------------------|
| 0    | `0x01` | FLAG_SIGNED | Ed25519 signature is present (see §4.7).     |

All other bits MUST be 0. A decoder MUST reject blobs with unknown flag bits set.

### 4.3 Mode Values

| Value | Name       | Description                                               |
|-------|------------|-----------------------------------------------------------|
| `0`   | `clear`    | No encryption; payload is stored verbatim.                |
| `1`   | `password` | Argon2id KDF + AES-256-GCM encryption.                   |
| `2`   | `pubkey`   | NaCl SealedBox key encapsulation + AES-256-GCM encryption.|

### 4.4 Clear Mode (`mode = 0`)

In clear mode, the payload is not encrypted. The QFSP blob is stored verbatim after the
header. This mode is intended for unsigned or signed-but-unencrypted transport.

**Unsigned clear layout:**

```
Offset | Length      | Type  | Field   | Description
-------|-------------|-------|---------|------------------------------------------
0      | 4           | bytes | magic   | "QFSC"
4      | 1           | uint8 | version | 6
5      | 1           | uint8 | mode    | 0
6      | 1           | uint8 | flags   | 0x00 (unsigned)
7      | payload_len | bytes | payload | QFSP blob verbatim
```

Header size: **7 bytes** (unsigned).

**Signed clear layout:**

```
Offset | Length      | Type  | Field           | Description
-------|-------------|-------|-----------------|------------------------------------------
0      | 4           | bytes | magic           | "QFSC"
4      | 1           | uint8 | version         | 6
5      | 1           | uint8 | mode            | 0
6      | 1           | uint8 | flags           | 0x01 (FLAG_SIGNED)
7      | 8           | bytes | signer_key_id   | First 8 bytes of SHA-256(verify_key)
15     | 32          | bytes | signer_verify_key| Ed25519 public verify key
47     | payload_len | bytes | payload         | QFSP blob verbatim
47+PL  | 64          | bytes | signature       | Ed25519 signature (see §4.7)
```

Header size: **47 bytes** (signed).

### 4.5 Password Mode (`mode = 1`)

Password mode uses Argon2id to derive an AES-256-GCM key from a password. The envelope
stores all KDF parameters explicitly so the decoder can reconstruct the key without
any out-of-band configuration.

**Unsigned password layout:**

```
Offset | Length      | Type   | Field             | Description
-------|-------------|--------|-------------------|------------------------------------------
0      | 4           | bytes  | magic             | "QFSC"
4      | 1           | uint8  | version           | 6
5      | 1           | uint8  | mode              | 1
6      | 1           | uint8  | flags             | 0x00 (unsigned)
7      | 16          | bytes  | salt              | Argon2id salt (CSPRNG; see §8.5)
23     | 12          | bytes  | nonce             | AES-GCM nonce (CSPRNG; see §8.2)
35     | 9           | bytes  | kdf_block         | KDF parameters (see §4.5.1)
44     | ct_len      | bytes  | ciphertext_tag    | AES-256-GCM ciphertext + 16-byte auth tag
```

Header size: **44 bytes** (unsigned).

**Signed password layout:**

```
Offset | Length      | Type   | Field             | Description
-------|-------------|--------|-------------------|------------------------------------------
0–6    | 7           | bytes  | (common header)   | As above
7      | 16          | bytes  | salt              |
23     | 12          | bytes  | nonce             |
35     | 9           | bytes  | kdf_block         |
44     | 8           | bytes  | signer_key_id     |
52     | 32          | bytes  | signer_verify_key |
84     | ct_len      | bytes  | ciphertext_tag    | AES-256-GCM ciphertext + 16-byte auth tag
84+CTL | 64          | bytes  | signature         | Ed25519 signature
```

Header size: **84 bytes** (signed).

#### 4.5.1 KDF Block (9 bytes)

The KDF block immediately follows the nonce field. It encodes all Argon2id parameters:

```
Offset within | Length | Type   | Field             | Description
kdf_block     |        |        |                   |
--------------|--------|--------|-------------------|----------------------------------
0             | 1      | uint8  | kdf_algorithm     | 0x01 = Argon2id (only valid value)
1             | 4      | uint32 | kdf_memory_kib    | Memory in kibibytes (big-endian)
5             | 1      | uint8  | kdf_time_cost     | Number of iterations
6             | 1      | uint8  | kdf_parallelism   | Degree of parallelism
7             | 1      | uint8  | kdf_salt_length   | Salt length in bytes (currently 16)
8             | 1      | uint8  | kdf_output_length | Output key length in bytes (currently 32)
```

Struct format (Python): `struct.pack(">BIBBBB", algo, mem_kib, time, parallel, salt_len, out_len)`

**Constraints enforced by the reference implementation:**

| Field             | Min         | Max              | Notes                      |
|-------------------|-------------|------------------|----------------------------|
| `kdf_algorithm`   | `0x01`      | `0x01`           | Only Argon2id is defined.  |
| `kdf_memory_kib`  | 8 KiB       | 4 194 304 KiB    | 4 GiB upper bound.         |
| `kdf_time_cost`   | 1           | 255              |                            |
| `kdf_parallelism` | 1           | 255              |                            |
| `kdf_salt_length` | 1           | 255              | Reference impl uses 16.    |
| `kdf_output_length`| 1          | 255              | Reference impl uses 32.    |

A decoder MUST read `kdf_algorithm`, `kdf_memory_kib`, `kdf_time_cost`, `kdf_parallelism`,
`kdf_salt_length`, and `kdf_output_length` from the envelope and use exactly those values for
key derivation. A decoder MUST NOT substitute its own defaults.

A decoder MUST reject envelopes where `kdf_algorithm != 0x01` with a clear error message
indicating an unsupported KDF algorithm.

#### 4.5.2 Reference KDF Profiles (Non-Normative)

The reference implementation defines three named profiles as starting points. Implementations
MUST NOT hardcode these profiles — the envelope parameters are always authoritative.

| Profile name   | `kdf_memory_kib` | `kdf_time_cost` | `kdf_parallelism` |
|----------------|-----------------|-----------------|-------------------|
| `interactive`  | 65 536 (64 MiB) | 3               | 1                 |
| `default`      | 262 144 (256 MiB)| 3              | 1                 |
| `sensitive`    | 1 048 576 (1 GiB)| 4              | 1                 |

The `default` profile (256 MiB / 3 iterations) is the recommended baseline for new envelopes.
The `interactive` profile (64 MiB) is used in the test vectors to keep CI run times short.

#### 4.5.3 Password Requirements

The reference implementation enforces a minimum password length of **14 characters** (Unicode
code points, not bytes). Implementations SHOULD enforce at least this minimum.

#### 4.5.4 AAD Construction for Password Mode

AES-256-GCM uses the entire envelope header as Additional Authenticated Data (AAD). For
password mode, the AAD is:

- **Unsigned:** bytes 0–43 of the envelope (magic + version + mode + flags + salt + nonce + kdf_block)
- **Signed:** bytes 0–83 of the envelope (above + signer_key_id + signer_verify_key)

The AAD MUST include the signer block when present. A decoder MUST pass the complete header
(up to but not including the ciphertext) as the AAD argument to AES-GCM decryption.

### 4.6 Public-Key Mode (`mode = 2`)

Public-key mode uses NaCl's anonymous sealed box construction (X25519 ECDH + XSalsa20-Poly1305)
to encrypt a randomly generated 32-byte AES-256-GCM session key. The session key then encrypts
the QFSP payload.

**Unsigned pubkey layout:**

```
Offset | Length     | Type   | Field             | Description
-------|------------|--------|-------------------|------------------------------------------
0      | 4          | bytes  | magic             | "QFSC"
4      | 1          | uint8  | version           | 6
5      | 1          | uint8  | mode              | 2
6      | 1          | uint8  | flags             | 0x00 (unsigned)
7      | 8          | bytes  | recipient_key_id  | First 8 bytes of SHA-256(recipient_pub_key)
15     | 2          | uint16 | sealed_len        | Length of sealed session key blob (typically 80)
17     | 12         | bytes  | nonce             | AES-GCM nonce (CSPRNG; see §8.5)
29     | sealed_len | bytes  | sealed            | NaCl SealedBox output (see §4.6.1)
29+SL  | ct_len     | bytes  | ciphertext_tag    | AES-256-GCM ciphertext + 16-byte auth tag
```

Header size (before `sealed`): **29 bytes** (unsigned).

**Signed pubkey layout:**

```
Offset | Length     | Type   | Field              | Description
-------|------------|--------|--------------------|------------------------------------------
0–6    | 7          | bytes  | (common header)    |
7      | 8          | bytes  | recipient_key_id   |
15     | 2          | uint16 | sealed_len         |
17     | 12         | bytes  | nonce              |
29     | 8          | bytes  | signer_key_id      |
37     | 32         | bytes  | signer_verify_key  |
69     | sealed_len | bytes  | sealed             |
69+SL  | ct_len     | bytes  | ciphertext_tag     | AES-256-GCM ciphertext + 16-byte auth tag
69+SL+CTL | 64     | bytes  | signature          | Ed25519 signature
```

Header size (before `sealed`): **69 bytes** (signed).

#### 4.6.1 NaCl SealedBox Construction

The `sealed` field is produced by libsodium's `crypto_box_seal` (NaCl `SealedBox`):

1. The encoder generates an ephemeral X25519 key pair `(epk, esk)` from CSPRNG.
2. Compute the shared secret: `X25519(esk, recipient_pub_key)`.
3. Derive an XSalsa20-Poly1305 key and nonce from `epk ∥ recipient_pub_key` via HSalsa20.
4. Encrypt the 32-byte session key under that key+nonce.
5. Output: `epk (32 bytes) ∥ Poly1305_mac (16 bytes) ∥ encrypted_session_key (32 bytes)`.

The total `sealed` output for a 32-byte input is always **80 bytes**. The encoder MUST set
`sealed_len = 80` in the envelope header.

Because `epk` is freshly random for each encryption, pubkey-mode envelopes are
**non-deterministic**: encoding the same payload twice yields different `sealed` bytes.
Test vectors for pubkey mode are therefore not byte-verified; they are verified by successful
decryption only (see §10.1).

#### 4.6.2 AAD Construction for Pubkey Mode

The AES-256-GCM AAD for pubkey mode is the envelope header **up to and including the optional
signer block, but NOT including the `sealed` field**:

- **Unsigned:** bytes 0–28 (magic + version + mode + flags + recipient_key_id + sealed_len + nonce)
- **Signed:** bytes 0–68 (above + signer_key_id + signer_verify_key)

The `sealed` field is authenticated by the NaCl Poly1305 MAC, not by AES-GCM AAD.

A decoder MUST pass only the header portion (excluding `sealed`) as the AES-GCM AAD.

#### 4.6.3 Recipient Key ID

`recipient_key_id` is the first 8 bytes of `SHA-256(recipient_x25519_public_key)`. The decoder
MUST compare this value to `SHA-256(derived_public_key)[:8]` (where `derived_public_key` is
the public key corresponding to the provided private key) and MUST reject the envelope if they
do not match.

### 4.7 Ed25519 Signature

When `flags & FLAG_SIGNED == FLAG_SIGNED`, the Ed25519 signature field is appended at the
very end of the envelope blob, after the ciphertext (or plaintext payload in clear mode).

#### 4.7.1 Signer Block

When signing is enabled, the signer block is inserted into the header immediately after the
mode-specific fields and before the ciphertext/payload:

```
Offset (mode-specific) | Length | Type  | Field              | Description
-----------------------|--------|-------|--------------------|--------------------------------------
+0                     | 8      | bytes | signer_key_id      | First 8 bytes of SHA-256(verify_key)
+8                     | 32     | bytes | signer_verify_key  | Raw Ed25519 public verify key (32 bytes)
```

Total signer block size: **40 bytes**.

The signer block MUST be included in the AAD for AES-GCM authentication (see §4.5.4 and §4.6.2).

#### 4.7.2 Signature Computation

The 64-byte Ed25519 signature is computed over the entire envelope blob excluding the
signature itself:

```
signature = Ed25519_sign(signing_private_key, header ∥ [sealed] ∥ ciphertext_or_payload)
```

For pubkey mode, `[sealed]` is the sealed session key blob. For clear and password modes,
there is no `[sealed]`.

The signed region is everything from byte 0 to the last byte before the 64-byte signature.

#### 4.7.3 Verification Order

A decoder MUST verify the Ed25519 signature **before** attempting decryption. If the signature
is invalid, the decoder MUST reject the blob and MUST NOT proceed to decryption. This ordering
prevents chosen-ciphertext attacks and ensures integrity under any key.

#### 4.7.4 Key IDs

`signer_key_id` is the first 8 bytes of `SHA-256(signer_verify_key)`. It is an identifier for
display and indexing purposes; it is NOT a security-critical field. The actual verify key is
in `signer_verify_key` and is used for signature verification.

### 4.8 Version Rejection

A decoder MUST check the version byte at offset 4.

- If `version == 5`, the decoder MUST reject with the error: "QFSC v5 envelopes are not
  supported. QRFS is pre-1.0 and does not commit to backward compatibility for envelope
  versions."
- If `version != 6` and `version != 5`, the decoder MUST reject with an appropriate error.

---

## 5. QRC3 — Chunk Format

The `QRC3` format splits a `QFSC` envelope blob into fixed-size chunks, each suitable for
embedding in a single QR symbol. Every chunk carries a header that allows full reassembly
without any external index or manifest.

### 5.1 Magic and Version

```
Offset 0:  51 52 43 33  ("QRC3")
Offset 4:  03           (version = 3)
```

A parser MUST reject any blob whose first 4 bytes are not `QRC3` or whose version byte at
offset 4 is not `3`, with a clear error message. QRC1, QRC2, and other formats are not
supported.

### 5.2 Binary Layout

```
Offset | Length      | Type   | Field        | Description
-------|-------------|--------|--------------|-------------------------------------------
0      | 4           | bytes  | magic        | ASCII "QRC3"
4      | 1           | uint8  | version      | 3
5      | 16          | bytes  | file_id      | Random 16-byte file identifier (CSPRNG)
21     | 1           | uint8  | kind         | 0=data, 1=parity
22     | 1           | uint8  | fec_type     | 0=none, 1=xor, 2=rs
23     | 4           | uint32 | index        | Data-stream index (see §5.3)
27     | 4           | uint32 | total        | Total number of data chunks in this file
31     | 2           | uint16 | payload_len  | Length of the payload field in bytes
33     | 4           | uint32 | group_index  | FEC group number (0-based)
37     | 2           | uint16 | group_size   | Nominal data chunks per group (0 if no FEC)
39     | 2           | uint16 | parity_count | Number of parity chunks per group
41     | 2           | uint16 | parity_index | Parity position within group (see §5.4)
43     | payload_len | bytes  | payload      | Data or parity bytes
```

Total header size: **43 bytes** (fixed).

Struct formats used by the reference implementation (Python):
- Main struct at offset 21: `struct.pack(">BBIIHIHH", kind, fec_type, index, total, len(payload), group_index, group_size, parity_count)`
- Parity index at offset 41: `struct.pack(">H", parity_index)`

### 5.3 Field Semantics

**`file_id`**: A randomly generated 16-byte value shared by ALL chunks belonging to the same
encoded file (both data and parity). A decoder MUST reject a set of chunks if more than one
distinct `file_id` value is present.

**`kind`**: Distinguishes data chunks from parity chunks. Data chunks carry portions of the
user payload; parity chunks carry FEC recovery data.

| Value | Name     | Meaning                                 |
|-------|----------|-----------------------------------------|
| `0`   | DATA     | This chunk carries user data.           |
| `1`   | PARITY   | This chunk carries FEC recovery data.   |

**`fec_type`**: The FEC scheme used for this chunk's group.

| Value | Name | Meaning                                          |
|-------|------|--------------------------------------------------|
| `0`   | NONE | No FEC for this file (all chunks are data).      |
| `1`   | XOR  | XOR parity (1 parity chunk per group).           |
| `2`   | RS   | Reed-Solomon parity (up to 4 parity per group).  |

All chunks in a file MUST have the same `fec_type` value.

**`index`**: For data chunks, this is the zero-based position of this chunk in the reassembled
byte stream. The first chunk (containing bytes 0 to payload_len-1 of the QFSC blob) has
`index = 0`. For parity chunks, `index` is set to `group_index`.

**`total`**: The total count of **data chunks** in the file. Parity chunks are not counted.
All chunks in a file MUST agree on `total`.

**`group_index`**: The zero-based index of the FEC group to which this chunk belongs. For
files without FEC, `group_index = 0`. For files with FEC, data chunk `i` belongs to group
`i // group_size`. All parity chunks for a group carry the same `group_index` as the group
they protect.

**`group_size`**: The nominal number of data chunks per FEC group. For files without FEC,
`group_size = 0`. The last group may have fewer data chunks than `group_size`.

Valid values: `0` (no FEC), `2`, `3`, `4`, `5`, `6`, `8`.

**`parity_count`**: The number of parity chunks generated per group. For files without FEC,
`parity_count = 0`. XOR FEC always has `parity_count = 1`. RS FEC supports 1–4.

### 5.4 `parity_index` Semantics

`parity_index` specifies which parity chunk this is within its group. The semantics depend
on `kind` and `fec_type`:

| `kind` | `fec_type` | `parity_index` value        | Meaning                                |
|--------|------------|----------------------------|----------------------------------------|
| DATA   | any        | 0 (SHOULD be 0; ignored)   | Not meaningful for data chunks.        |
| PARITY | XOR (1)    | 0                           | Always 0; XOR has exactly 1 parity.   |
| PARITY | RS (2)     | 0 .. parity_count-1         | Which RS parity vector this chunk is. |

A decoder MUST sort RS parity chunks by `parity_index` (ascending) before recovery.

### 5.5 Parity Payload Internal Structure

The payload of a parity chunk (`kind = 1`) is NOT raw parity bytes. It has a header that
records the original lengths of the data chunks in the group, enabling exact reconstruction
of variable-length chunks (the last chunk in a file may be shorter than `chunk_size`).

```
Offset within   | Length              | Type   | Field       | Description
parity payload  |                     |        |             |
----------------|---------------------|--------|-------------|-------------------------------
0               | 2                   | uint16 | meta_count  | Number of data chunks in group
2               | meta_count * 2      | uint16 | lengths[]   | Length of each data chunk payload
2 + meta_count*2| chunk_size          | bytes  | parity_bytes| XOR or RS parity vector
```

`meta_count` is the actual number of data chunks in this group (may be less than `group_size`
for the last group). `lengths[i]` is the original payload length of data chunk `i` within the
group. `parity_bytes` is exactly `chunk_size` bytes.

Total parity payload size: `2 + 2*meta_count + chunk_size` bytes.

---

## 6. FEC Layer

QRFS provides two optional FEC schemes. Both operate **per group**: the encoder produces parity
from the data chunks within one group; the decoder recovers missing data chunks using only the
parity from the same group.

### 6.1 XOR FEC

XOR FEC adds exactly **one** parity chunk per group.

**Encoding:**

For a group of `k` data chunks with payloads `D[0], D[1], ..., D[k-1]`:

1. Pad each payload to exactly `chunk_size` bytes with zero bytes.
2. Compute `xor_bytes = D[0] XOR D[1] XOR ... XOR D[k-1]` (element-wise XOR).
3. Build the parity payload: `meta_count(uint16) ∥ len(D[0])(uint16) ∥ ... ∥ len(D[k-1])(uint16) ∥ xor_bytes`.
4. Set parity chunk fields: `kind=1, fec_type=1, index=group_index, parity_count=1, parity_index=0`.

**Recovery:** XOR can recover exactly **one** missing data chunk per group. If two or more
data chunks in a group are missing, XOR recovery MUST fail with a clear error.

**Recovery procedure (informative pseudocode):**

```python
# given: group data chunks (all but one present), one parity chunk
# output: recovered data chunk

lengths, parity_blob = decode_parity_payload(parity_chunk.payload)
recovered = parity_blob
for i, idx in enumerate(group_indexes):
    if idx in present_data_chunks:
        padded = present_data_chunks[idx].ljust(chunk_size, b'\x00')
        recovered = xor_bytes(recovered, padded)
# recovered is now the missing chunk, trimmed to lengths[missing_relative_index]
missing_rel = missing_index - group_start_index
recovered_chunk_data = recovered[:lengths[missing_rel]]
```

### 6.2 Reed-Solomon FEC

RS FEC adds `P` parity chunks per group, where `1 ≤ P ≤ 4` and `P < group_size`.

**Encoding:**

For a group of `k` data chunks with payloads `D[0], ..., D[k-1]`:

1. Pad each payload to exactly `chunk_size` bytes with zero bytes.
2. For each byte position `pos` in `[0, chunk_size)`:
   - Form a message vector: `msg = [D[0][pos], D[1][pos], ..., D[k-1][pos]]`.
   - Encode with Reed-Solomon(k, k+P): `codeword = RS_encode(msg)`.
   - The last `P` symbols of the codeword are the parity bytes at position `pos`.
   - Store `parity_byte[pi][pos] = codeword[k + pi]` for each `pi ∈ [0, P)`.
3. Build `P` parity chunks. Chunk `pi` has:
   - `payload = meta_count(uint16) ∥ lengths[] ∥ parity_byte[pi]`
   - `kind=1, fec_type=2, parity_count=P, parity_index=pi`

**Recovery:** RS recovery treats missing chunks as **known erasures**. A group can recover any
combination of up to `P` missing chunks (data and/or parity combined) per group.

**Recovery procedure (informative pseudocode):**

```python
# given: partial data_map {index: payload}, parity_map {parity_index: parity_bytes}
# output: complete data_map with missing data chunks filled in

rsc = RSCodec(P)  # reedsolo library
for pos in range(chunk_size):
    symbols = bytearray()
    erase_positions = []
    for rel, global_idx in enumerate(expected_indexes):
        if global_idx in data_map:
            symbols.append(data_map[global_idx].padded[pos])
        else:
            symbols.append(0)  # erasure placeholder
            erase_positions.append(rel)
    for pi in range(P):
        if pi in parity_map:
            symbols.append(parity_map[pi][pos])
        else:
            symbols.append(0)
            erase_positions.append(k + pi)
    decoded = rsc.decode(bytes(symbols), erase_pos=erase_positions)[0]
    # fill in recovered bytes for missing chunks
    for rel, global_idx in enumerate(expected_indexes):
        if global_idx not in data_map:
            data_map[global_idx][pos] = decoded[rel]
# trim each recovered chunk to its original length from lengths[]
```

### 6.3 Reassembly Algorithm

A conforming decoder MUST implement the following reassembly algorithm:

1. Parse all available raw blobs into `Chunk` objects.
2. Verify all chunks share the same `file_id`. Reject if not.
3. Verify all chunks agree on `total`. Reject if not.
4. Group chunks by `group_index`. Each group contains data and/or parity chunks.
5. For each group:
   a. If all data chunks for this group are present: no FEC needed; add to result map.
   b. If some data chunks are missing and `fec_type = XOR`: apply XOR recovery (§6.1).
   c. If some data chunks are missing and `fec_type = RS`: apply RS recovery (§6.2).
6. Verify all `total` data chunks are present after recovery. If any are still missing, fail.
7. Concatenate payloads `by_index[0] ∥ by_index[1] ∥ ... ∥ by_index[total-1]`.
8. The result is the `QFSC` blob, ready for decryption.

---

## 7. Base45 Carrier Encoding

Before being written into a QR symbol, each `QRC3` chunk blob MUST be encoded with **Base45**
as defined in [RFC 9285].

The Base45 alphabet is:

```
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:
```

Each pair of bytes encodes to 3 characters; a single remaining byte encodes to 2 characters.

**Rationale:** Base45 maps to QR alphanumeric mode, which has better density than binary mode
for the character set used. It also remains human-inspectable and portable across text-processing
layers.

A decoder reading QR symbols MUST strip all whitespace before Base45 decoding, then parse the
result as a `QRC3` chunk.

---

## 8. Cryptographic Primitives

This section documents all cryptographic algorithms used by QRFS, with enough detail for a
re-implementer to select compatible libraries.

### 8.1 Argon2id (KDF for Password Mode)

| Parameter      | Value / Description                                         |
|----------------|-------------------------------------------------------------|
| Algorithm      | Argon2id (RFC 9106, §4)                                     |
| Output length  | 32 bytes (as specified in `kdf_output_length`)              |
| Salt           | 16 random bytes from CSPRNG (as specified in `kdf_salt_length`)|
| Memory         | As specified in `kdf_memory_kib` (kibibytes)                |
| Iterations     | As specified in `kdf_time_cost`                             |
| Parallelism    | As specified in `kdf_parallelism`                           |
| Password encoding | UTF-8 bytes of the password string                      |

Reference: [RFC 9106] "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
Applications."

The reference implementation uses PyNaCl's `nacl.pwhash.argon2id.kdf`, which wraps
libsodium's `crypto_pwhash_ALG_ARGON2ID13`.

A decoder MUST use exactly the parameters from the KDF block in the envelope. It MUST NOT
ignore or override any parameter.

### 8.2 AES-256-GCM (Authenticated Encryption)

| Parameter      | Value / Description                                         |
|----------------|-------------------------------------------------------------|
| Key size       | 32 bytes (256 bits)                                         |
| Nonce size     | 12 bytes (96 bits)                                          |
| Tag size       | 16 bytes (128 bits) — appended to ciphertext                |
| AAD            | Envelope header (see §4.5.4 and §4.6.2)                   |

Reference: [NIST SP 800-38D] "Recommendation for Block Cipher Modes of Operation: Galois/Counter
Mode (GCM) and GMAC."

For password mode, the AES key is the Argon2id output (32 bytes). For pubkey mode, the AES key
is the randomly generated session key decapsulated from the SealedBox (32 bytes).

The 12-byte nonce is stored in the envelope header and MUST be generated from CSPRNG for each
new encryption.

The GCM tag (16 bytes) is appended to the ciphertext in the envelope. The combined
`ciphertext_tag` field length is `len(plaintext) + 16`.

### 8.3 X25519 / NaCl SealedBox (Key Encapsulation)

| Parameter      | Value / Description                                         |
|----------------|-------------------------------------------------------------|
| Key exchange   | X25519 (RFC 7748)                                           |
| Symmetric      | XSalsa20-Poly1305 (NaCl `secretbox`)                       |
| Construction   | libsodium `crypto_box_seal` (anonymous sender)              |
| Key size       | 32 bytes for both public and private keys                   |

Reference: [RFC 7748] "Elliptic Curves for Security."

The SealedBox is anonymous: the sender does not authenticate themselves through the
encapsulation. Authentication is provided separately by the optional Ed25519 signature.

The reference implementation uses PyNaCl's `nacl.public.SealedBox`.

### 8.4 Ed25519 (Digital Signatures)

| Parameter      | Value / Description                                         |
|----------------|-------------------------------------------------------------|
| Signature size | 64 bytes                                                    |
| Public key     | 32 bytes (Ed25519 verify key)                               |
| Private key    | 32 bytes (Ed25519 signing key seed)                         |
| Hash           | SHA-512 (internal to Ed25519)                               |

Reference: [RFC 8032] "Edwards-Curve Digital Signature Algorithm (EdDSA)."

The signature covers the entire envelope blob excluding the final 64-byte signature field
(see §4.7.2).

Verification MUST precede decryption (see §4.7.3).

The reference implementation uses PyNaCl's `nacl.signing.SigningKey`.

### 8.5 Random Sources

All salts, nonces, file IDs, ephemeral keys, and session keys MUST be generated from a CSPRNG.

In the reference implementation, `os.urandom()` (Python standard library) is used, which
delegates to `/dev/urandom` on Linux, `CryptGenRandom` on Windows, and equivalent OS-level
CSPRNGs on other platforms.

An implementation MUST NOT use a weak or seeded PRNG for any cryptographic material.
Deterministic generation of salts and nonces is supported only for test vector generation
(via `_salt`, `_nonce`, `_file_id` test parameters) and MUST NOT be used in production.

### 8.6 Key IDs

Key IDs are short, non-secret identifiers derived from public keys for lookup and display.

**Encryption key ID (`recipient_key_id` in QFSC pubkey mode):**

```
key_id = SHA-256(x25519_public_key)[:8]
```

**Signing key ID (`signer_key_id` in QFSC signer block):**

```
signing_key_id = SHA-256(ed25519_verify_key)[:8]
```

Both are 8-byte truncations of the SHA-256 digest of the corresponding 32-byte public key.
These are NOT cryptographic commitments; they are display-only identifiers. The actual public
key in the envelope is the authoritative identifier.

---

## 9. PDF Layout (Informative)

> **This section is informative, not normative.** A conforming implementation MAY produce QR
> symbols in any container — individual PNG files, a PDF, a video stream, thermal printer
> output, or any other medium. The `QRC3` chunk-level metadata is sufficient for complete
> reassembly, regardless of the container.

The reference Python implementation produces PDF artifacts using the following layout:

- **Page size:** A4 (210 mm × 297 mm)
- **Grid:** 5 columns × 6 rows = 30 QR symbols per page
- **QR border:** 2 modules
- **QR box size:** 3 pixels per module (for page image generation)
- **ECC level:** Selectable (L, M, Q, H); affects QR density

**Page footer labels** distinguish chunk types:

- Data chunks: `D{index+1}/{total}` (e.g., `D5/12` = data chunk 5 of 12)
- Parity chunks: `P{parity_index+1}/{parity_count} G{group_index+1}` (e.g., `P1/2 G3`)

**Chunk interleaving:** The reference implementation applies a stride-based reordering of
chunk positions within each page to spread nearby logical chunks apart physically. This is a
page-layout heuristic, not a format requirement.

The metadata manifest JSON file (written alongside the PDF) is a convenience artifact for
auditing and reproducibility. It is NOT required for decoding; all necessary information is
in the `QRC3` chunk headers.

---

## 10. Conformance

### 10.1 Test Vectors

The canonical byte-level reference for this specification is in `tests/vectors/`. Every file
is listed in `tests/vectors/manifest.json` with its SHA-256 digest and a `"deterministic"`
flag.

**Deterministic files** (`"deterministic": true`): a conforming Level 3 implementation MUST
produce bytes identical to these files for the same inputs and the fixed test fixtures
specified in the manifest. Any byte change to a deterministic file is a format break.

**Non-deterministic files** (`"deterministic": false`): pubkey-mode envelopes use random
ephemeral keys. Conforming implementations MUST be able to decrypt these envelopes using the
test private key at `tests/vectors/keys/recipient_x25519.sk`, but are NOT required to produce
identical bytes.

**Fixed test fixtures** (from `tests/vectors/manifest.json`):

```json
{
  "file_id_hex":        "00112233445566778899aabbccddeeff",
  "argon2_salt_hex":    "0123456789abcdef0123456789abcdef",
  "aes_gcm_nonce_hex":  "deadbeefcafebabedeadbeef",
  "password":           "correct horse battery staple xx",
  "chunk_size":         100
}
```

The KDF profile used for all password test vectors is `interactive` (64 MiB, 3 iterations,
parallelism 1).

### 10.2 Conformance Levels

**Level 1 — Reader:** The implementation can decode and decrypt all valid QRFS artifacts
(all three QFSC modes, with and without signatures, with and without FEC).

**Level 2 — Writer:** The implementation can produce valid QRFS artifacts that any Level 1
implementation can decode and decrypt.

**Level 3 — Round-trip:** The implementation is both Level 1 and Level 2, and additionally
produces byte-identical output to the deterministic test vectors for the fixed test inputs
and fixtures.

The Python reference implementation (`flyingsurveyor/qrfs`) is Level 3.

Future implementations (e.g., a JavaScript browser decoder) MUST self-declare which level
they target. A Level 1 declaration is sufficient for a read-only decoder.

### 10.3 Minimum Acceptance Criteria

A conforming implementation MUST:

- Correctly parse and reject invalid magic bytes with a clear error.
- Correctly reject QFSC v5 (and earlier) with the specified error message.
- Correctly reject QRC1, QRC2 (and earlier chunk formats) with a clear error.
- Correctly derive the AES key using Argon2id with parameters from the KDF block (password mode).
- Correctly open the NaCl SealedBox to recover the session key (pubkey mode).
- Correctly verify Ed25519 signatures before decryption when FLAG_SIGNED is set.
- Correctly use AAD as specified in §4.5.4 (password) and §4.6.2 (pubkey).
- Correctly reconstruct the original file from `QRC3` chunks, including FEC recovery.

---

## 11. Security Considerations

### 11.1 Threat Model

QRFS is designed to protect against:

- **Passive observation of stored or transmitted artifacts:** In password or pubkey mode, the
  QFSP payload (including filename, MIME type, and file contents) is encrypted and
  authenticated. An observer who obtains the printed QR pages cannot recover the plaintext
  without the password or recipient private key.
- **Integrity tampering:** AES-256-GCM with header AAD authenticates both the payload and
  the envelope metadata. Any modification to the envelope will cause decryption to fail.
- **Recipient impersonation (pubkey mode):** The recipient key ID in the envelope binds the
  ciphertext to a specific recipient. A decoder verifies that the provided private key matches
  the `recipient_key_id` before attempting decapsulation.

### 11.2 What QRFS Does Not Protect Against

- **Side-channel attacks during decoding:** QRFS does not implement constant-time decoding,
  cache-timing mitigations, or speculative-execution defenses.
- **RAM scraping post-decryption:** Once decrypted, the plaintext is in process memory and is
  not explicitly zeroed by the reference implementation.
- **Weak passwords:** Argon2id raises the cost of brute-force attacks, but a very short or
  common password can still be attacked. The minimum 14-character requirement is a floor, not
  a security guarantee.
- **QR code substitution attacks:** If an adversary can replace printed pages before they are
  scanned, the decoding session processes attacker-controlled chunks. Using the signature mode
  (`FLAG_SIGNED`) with a known verify key mitigates this by allowing the decoder to reject
  unsigned or incorrectly signed artifacts.
- **Quantum adversaries:** Neither X25519 nor Ed25519 provides post-quantum security. AES-256
  is considered adequate against quantum adversaries (Grover's algorithm halves the effective
  key length to 128 bits, which remains secure).

### 11.3 Password Strength

The reference implementation enforces a minimum of **14 characters**. Implementers SHOULD
enforce at least this minimum. Users SHOULD choose passwords from a large entropy pool
(diceware, random character strings). The `sensitive` KDF profile (1 GiB, 4 iterations)
raises brute-force cost significantly but does not compensate for a weak password.

### 11.4 KDF Profile Selection Trade-offs

| Profile       | Memory   | Time (iterations) | Security level | Recommended use                       |
|---------------|----------|-------------------|----------------|---------------------------------------|
| `interactive` | 64 MiB   | 3                 | Adequate       | Testing, constrained devices          |
| `default`     | 256 MiB  | 3                 | Good           | General use (OWASP baseline)          |
| `sensitive`   | 1 GiB    | 4                 | Strong         | Long-term archival, high-value data   |

The `default` profile is the recommended baseline for general use. Implementations targeting
severely constrained environments MAY use lower parameters, but MUST encode the actual
parameters used in the KDF block so decoders can adapt.

### 11.5 Forward Secrecy

Pubkey mode does **NOT** provide forward secrecy. The session key is encrypted to the
recipient's long-term X25519 public key. If the recipient's private key is compromised in the
future, all past pubkey-mode envelopes encrypted to that key can be decrypted.

Users requiring forward secrecy SHOULD rotate their key pair periodically and maintain old
private keys only in secure offline storage for the minimum required retention period.

### 11.6 Replay Protection

QRFS envelopes do not include timestamps or sequence numbers. QRFS itself provides no
anti-replay protection. Implementations layering QRFS over a transport protocol SHOULD add
their own anti-replay mechanism if needed.

### 11.7 AES-GCM Nonce Reuse

AES-256-GCM is catastrophically broken if the same (key, nonce) pair is used twice. The
reference implementation generates each nonce with `os.urandom(12)`. Implementations MUST
ensure nonce uniqueness. The 96-bit nonce space makes random collisions negligible in practice
for any reasonable number of encryptions per key, but implementations MUST NOT allow nonce
reuse.

---

## 12. Privacy Considerations

### 12.1 Filename and MIME Type

The filename and MIME type are stored inside the `QFSP` metadata JSON. Their confidentiality
depends on the QFSC mode:

- **Clear mode:** Filename and MIME type are visible to any observer who scans the QR codes.
- **Password mode:** Filename and MIME type are encrypted as part of the QFSP payload and are
  not revealed without the correct password.
- **Pubkey mode:** Same as password mode; not revealed without the recipient's private key.

### 12.2 File Size Leakage

The total size of the QRFS artifact (number of QR codes, total bytes) leaks an approximation
of the file size to any observer. The relationship between original file size and artifact size
depends on compression ratio, FEC overhead, and chunk configuration, but the approximation is
tight enough to reveal rough file size categories.

Padding to a fixed artifact size would mitigate this leakage, but padding is **not** defined
in QRFS v1.0 and is reserved for a future version.

### 12.3 Key IDs

The `recipient_key_id` (in pubkey mode) and `signer_key_id` (when signed) are visible in
the clear in the QFSC header, even in encrypted envelopes. An observer can use these to
identify which recipient key was used or who signed the envelope, even without decrypting the
payload.

---

## 13. IANA and Registry Considerations

QRFS does not currently request any IANA registrations.

Future versions MAY request IANA media type registrations:

- `application/vnd.qrfs.envelope` for `.qfsc` files (QFSC v6 cryptographic envelopes)
- `application/vnd.qrfs.payload` for `.qfsp` files (QFSP v1 file payload blobs)
- `application/vnd.qrfs.chunk` for `.qrc` files (QRC3 chunk blobs)

No IANA protocol parameters, algorithm identifiers, or registries are defined by this
specification. The KDF algorithm byte `0x01` (Argon2id) is an internal QRFS value and is
not registered with any external registry.

---

## 14. References

### 14.1 Normative References

| Identifier          | Title                                                       |
|---------------------|-------------------------------------------------------------|
| [RFC 2119]          | S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119, March 1997. |
| [RFC 9106]          | A. Biryukov et al., "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106, September 2021. |
| [NIST SP 800-38D]   | M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", NIST Special Publication 800-38D, November 2007. |
| [RFC 7748]          | A. Langley et al., "Elliptic Curves for Security", RFC 7748, January 2016. |
| [RFC 8032]          | S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. |
| [RFC 9285]          | P. Fältström et al., "The Base45 Data Encoding", RFC 9285, August 2022. |

### 14.2 Informative References

| Identifier          | Title                                                       |
|---------------------|-------------------------------------------------------------|
| [ISO/IEC 18004]     | ISO/IEC 18004:2015, "Information technology — Automatic identification and data capture techniques — QR Code bar code symbology specification." |
| [QRFS-README]       | `README.md` in this repository, QRFS reference implementation documentation. |
| [QRFS-FORMAT]       | `docs/FORMAT.md` in this repository, implementation-oriented format notes. |
| [QRFS-VECTORS]      | `tests/vectors/README.md` in this repository, conformance test vector specification. |
| [QRFS-SECURITY]     | `SECURITY.md` in this repository, threat model and vulnerability reporting. |
| [libsodium]         | https://libsodium.org — NaCl-compatible cryptographic library. |

---

## Appendix A — Worked Example

This appendix traces the encoding of `tests/vectors/inputs/small_text.txt` (633 bytes of
ASCII text) through all three format layers, with byte-precise annotation.

### A.1 QFSP v1 — `tests/vectors/packaged/small_text.qfsp`

File: 491 bytes.

**Hex dump, first 128 bytes:**

```
Offset  Hex                                              ASCII
──────  ───────────────────────────────────────────────  ────────────────
00000   51 46 53 50  01  00 00 00 5C  00 00 01 82        QFSP · ··· \ ···
          ╰──QFSP──╯ │   ╰──meta 92─╯  ╰payload 386╯
                     │
                     └─ version=1

00013   7B 22 66 69 6C 65 6E 61  6D 65 22 3A 22 73 6D 61   {"filename":"sma
00029   6C 6C 5F 74 65 78 74 2E  74 78 74 22 2C 22 6D 69   ll_text.txt","mi
00045   6D 65 5F 74 79 70 65 22  3A 22 74 65 78 74 2F 70   me_type":"text/p
00061   6C 61 69 6E 22 2C 22 63  6F 6D 70 72 65 73 73 65   lain","compresse
00077   64 22 3A 74 72 75 65 2C  22 6F 72 69 67 69 6E 61   d":true,"origina
00093   6C 5F 73 69 7A 65 22 3A  36 33 33 7D               l_size":633}
            └──────────────── metadata ends at offset 104 ───────────────┘

00105   78 DA 4D 52 C1 6E DB 30  ...
          ╰─zlib header (compression level 9)
```

**Field table:**

```
Offset | Length | Value                  | Field
-------|--------|------------------------|-------------------------------------------
0      | 4      | 51 46 53 50 ("QFSP")  | magic
4      | 1      | 01                     | version = 1
5      | 4      | 00 00 00 5C (= 92)    | metadata_len = 92 bytes
9      | 4      | 00 00 01 82 (= 386)   | payload_len = 386 bytes
13     | 92     | {"filename":...}       | metadata JSON (UTF-8)
105    | 386    | 78 DA ...              | zlib-compressed file bytes
```

The zlib magic `78 DA` indicates the default compression level (deflate + maximum compression).
The encoder compressed 633 bytes → 386 bytes (61% ratio), so `compressed: true`.

### A.2 QFSC v6 Clear Mode — `tests/vectors/envelopes/clear/small_text.qfsc`

File: 498 bytes = 7 (header) + 491 (QFSP payload).

**Hex dump, first 16 bytes:**

```
Offset  Hex                            Notes
──────  ─────────────────────────────  ──────────────────────────────────
00000   51 46 53 43  06  00  00         QFSC ─ v6 ─ clear ─ unsigned
          ╰──QFSC──╯ │   │   └─ flags=0x00 (no signature)
                     │   └─ mode=0 (clear)
                     └─ version=6
00007   51 46 53 50 01 00 00 00 5C ...  ← QFSP blob starts here
```

**Field table:**

```
Offset | Length | Value                 | Field
-------|--------|-----------------------|-------------------------------------------
0      | 4      | 51 46 53 43 ("QFSC") | magic
4      | 1      | 06                    | version = 6
5      | 1      | 00                    | mode = 0 (clear)
6      | 1      | 00                    | flags = 0x00 (unsigned)
7      | 491    | 51 46 53 50 01 ...   | QFSP payload (verbatim)
```

### A.3 QFSC v6 Password Mode — `tests/vectors/envelopes/password_interactive/small_text.qfsc`

File: 551 bytes = 44 (header) + 507 (ciphertext + 16-byte GCM tag).

**Field table:**

```
Offset | Length | Value                  | Field
-------|--------|------------------------|-------------------------------------------
0      | 4      | 51 46 53 43 ("QFSC") | magic
4      | 1      | 06                    | version = 6
5      | 1      | 01                    | mode = 1 (password)
6      | 1      | 00                    | flags = 0x00 (unsigned)
7      | 16     | 01 23 45 67 89 AB CD  | salt (from test fixture)
       |        | EF 01 23 45 67 89 AB  |
       |        | CD EF                 |
23     | 12     | DE AD BE EF CA FE BA  | nonce (from test fixture)
       |        | BE DE AD BE EF        |
35     | 1      | 01                    | kdf_algorithm = 0x01 (Argon2id)
36     | 4      | 00 01 00 00 (= 65536) | kdf_memory_kib = 65536 (64 MiB)
40     | 1      | 03                    | kdf_time_cost = 3
41     | 1      | 01                    | kdf_parallelism = 1
42     | 1      | 10 (= 16)             | kdf_salt_length = 16
43     | 1      | 20 (= 32)             | kdf_output_length = 32
44     | 507    | (binary ciphertext)   | AES-256-GCM ciphertext + 16-byte tag
```

### A.4 QFSC v6 Pubkey Mode — `tests/vectors/envelopes/pubkey/small_text.qfsc`

File: 616 bytes = 29 (header) + 80 (sealed) + 507 (ciphertext + 16-byte GCM tag).

**Field table:**

```
Offset | Length | Value                 | Field
-------|--------|-----------------------|-------------------------------------------
0      | 4      | 51 46 53 43 ("QFSC") | magic
4      | 1      | 06                    | version = 6
5      | 1      | 02                    | mode = 2 (pubkey)
6      | 1      | 00                    | flags = 0x00 (unsigned)
7      | 8      | FF 39 79 ED 4C B6 B9 63| recipient_key_id (SHA-256(pub_key)[:8])
15     | 2      | 00 50 (= 80)          | sealed_len = 80
17     | 12     | (random nonce)        | AES-GCM nonce
29     | 80     | (NaCl SealedBox)      | sealed session key
109    | 507    | (binary ciphertext)   | AES-256-GCM ciphertext + 16-byte tag
```

### A.5 QRC3 Chunk — `tests/vectors/chunks/small_text/000.qrc`

File: 143 bytes = 43 (header) + 100 (payload = first 100 bytes of the 498-byte QFSC blob).

**Hex dump, first 48 bytes:**

```
Offset  Hex                                              Notes
──────  ───────────────────────────────────────────────  ────────────────────────────
00000   51 52 43 33  03                                  "QRC3" version=3
00005   00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF file_id (16 bytes)
00021   00  00  00 00 00 00  00 00 00 05  00 64          kind=0 fec=0 idx=0 tot=5 len=100
         │   │  ╰──index──╯  ╰──total──╯  ╰paylen╯
         │   └─ fec_type=0 (none)
         └─ kind=0 (data)
00033   00 00 00 00  00 00  00 00  00 00                 g_idx=0 g_sz=0 par_cnt=0 par_idx=0
         ╰─g_index─╯  ╰gsz╯  ╰pcnt╯  ╰pidx╯
00043   51 46 53 43 06 00 00 ...                         payload: first 100 bytes of QFSC
```

**Field table:**

```
Offset | Length | Value               | Field
-------|--------|---------------------|-------------------------------------------
0      | 4      | 51 52 43 33        | magic = "QRC3"
4      | 1      | 03                 | version = 3
5      | 16     | 00 11 22 33 ...    | file_id (fixed test value)
21     | 1      | 00                 | kind = 0 (data)
22     | 1      | 00                 | fec_type = 0 (none)
23     | 4      | 00 00 00 00 (= 0) | index = 0 (first chunk)
27     | 4      | 00 00 00 05 (= 5) | total = 5 data chunks
31     | 2      | 00 64 (= 100)     | payload_len = 100 bytes
33     | 4      | 00 00 00 00 (= 0) | group_index = 0
37     | 2      | 00 00 (= 0)       | group_size = 0 (no FEC)
39     | 2      | 00 00 (= 0)       | parity_count = 0 (no FEC)
41     | 2      | 00 00 (= 0)       | parity_index = 0 (unused for data)
43     | 100    | 51 46 53 43 06 ...| payload (bytes 0–99 of QFSC clear envelope)
```

The 498-byte QFSC clear envelope is split into 5 chunks: 4 × 100 bytes + 1 × 98 bytes
(chunk index 4), totalling 498 bytes.

### A.6 XOR Parity Chunk — `tests/vectors/chunks/small_text_fec_xor/p000.qrc`

This file demonstrates the parity payload structure. The fec_xor set uses group_size=3.

File: 151 bytes = 43 (header) + 108 (parity payload = 2 + 6 + 100).

**Field table:**

```
Offset | Length | Value               | Field
-------|--------|---------------------|-------------------------------------------
0–42   | 43     | (QRC3 header)      | kind=1, fec_type=1, index=0, total=5,
       |        |                     | payload_len=108, group_index=0,
       |        |                     | group_size=3, parity_count=1, parity_index=0
43     | 2      | 00 03 (= 3)        | meta_count = 3 (chunks 0, 1, 2 in group 0)
45     | 2      | 00 64 (= 100)      | lengths[0] = 100 (chunk 0 length)
47     | 2      | 00 64 (= 100)      | lengths[1] = 100 (chunk 1 length)
49     | 2      | 00 64 (= 100)      | lengths[2] = 100 (chunk 2 length)
51     | 100    | (XOR bytes)        | xor_bytes = D[0] XOR D[1] XOR D[2]
```

---

## Appendix B — Pre-1.0 Change Log

This appendix summarizes the format version history for context. All pre-1.0 versions are
incompatible with each other and with QRFS 1.0. No migration path is provided.

| Format   | Status      | Notes                                                             |
|----------|-------------|-------------------------------------------------------------------|
| QFSP v1  | **Current** | File payload format. No prior versions existed publicly.          |
| QFSC v6  | **Current** | Replaced v5 in pre-1.0 to add explicit KDF parameter block.      |
| QFSC v5  | Unsupported | Did not carry KDF parameters in the envelope; decoders hardcoded defaults. |
| QRC3     | **Current** | Replaced QRC1 and QRC2 in pre-1.0 to fix `parity_index` semantics. |
| QRC2     | Unsupported | `parity_index` semantics were incorrect.                         |
| QRC1     | Unsupported | Early chunk format, incompatible wire layout.                    |

**Summary of breaking changes from pre-1.0 to 1.0:**

1. **QFSC v5 → v6**: The QFSC envelope now carries a 9-byte KDF parameter block in the
   password-mode header. Decoders no longer need out-of-band KDF configuration. v5 envelopes
   are unconditionally rejected.

2. **QRC1/QRC2 → QRC3**: The `parity_index` field semantics were corrected. For XOR parity,
   `parity_index = 0`. For RS parity, `parity_index ∈ [0, parity_count-1]` (locally within
   the group). Older formats incorrectly aliased this field with `group_index`. Old chunk
   formats are unconditionally rejected.

3. **Lint and CI**: Pre-1.0 had broad per-file lint ignores. QRFS 1.0 enforces clean Ruff
   linting across all Python source files, with only a narrow exception for the test vector
   generator's intentional import order.

> QRFS 1.0 onward commits to documenting any future format changes explicitly in this document,
> with migration guidance and version bump rationale. The conformance test vectors under
> `tests/vectors/` are frozen at 1.0.
