# QRFS Manual Recovery Guide

This document explains how to recover QRFS payloads **without relying on the full QRFS Web UI**.
It is meant for technical users, auditors, emergency recovery, long-term archival scenarios,
and situations where only generic tools remain available.

It does **not** try to be the fastest path.
It tries to be the most understandable path.

## Reality check

There are three useful recovery levels:

1. **With QRFS itself**
   - easiest and most complete path
2. **With generic QR decoding tools plus a small script**
   - realistic emergency path
3. **By reimplementing the format from these docs**
   - slowest, but strongest for long-term recoverability

This guide focuses on levels 2 and 3.

## What you need

At minimum, you need a way to extract the raw QR payload strings.
That can come from:

- a flatbed scanner and a QR decoder
- phone photos and a QR decoder
- single QR captures already exported as text
- your own custom decoder pipeline

The important point is this:

**QRFS QR symbols contain Base45 text.**
So your decoder must give you the exact decoded text string, not a screenshot,
not OCR of the printed footer, and not a normalized or truncated approximation.

## Recommended mindset

Treat each QR symbol as carrying one opaque transport record.
Recovery works by:

1. collecting all Base45 strings
2. converting them back to chunk bytes
3. parsing chunk headers
4. grouping and ordering chunks
5. using FEC if needed
6. rebuilding the encrypted transport blob
7. decrypting or verifying it
8. unpacking the file

---

## Step 1. Collect QR payload strings

You need the **decoded QR content**, not the printed human label.

Good sources:

- `zbarimg`
- `pyzbar`
- browser-side or mobile QR scanners that preserve the exact text payload
- custom scripts against page images

Things to watch out for:

- duplicate reads of the same QR
- scanners that silently alter whitespace or punctuation
- scanners that return only a partial payload
- software that assumes URLs or normalizes text

QRFS uses Base45 text, so a correct scan should be a string made from this alphabet only:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:
```

---

## Step 2. Base45-decode each QR payload

Each QRFS QR symbol carries one chunk blob encoded with Base45.

In Python, the QRFS implementation uses the logic in `qrfs/core/utils.py`.
A compatible decoder can be implemented independently.

A decoded chunk must begin with one of these magics:

- `QRC1`
- `QRC2`
- `QRC3`

If it does not, either:

- the QR scan is corrupted
- the payload was not Base45-decoded correctly
- or the QR is not a QRFS chunk

---

## Step 3. Parse chunk headers

The critical fields are:

- `file_id`
- `index`
- `total`
- `kind` (data/parity)
- `group_index`
- `group_size`
- `fec_type`
- `parity_count`
- `parity_index`
- `payload`

You should immediately discard any chunk set that mixes different `file_id` values,
unless you are intentionally sorting multiple documents at once.

You should also verify that all chunks agree on the same `total` data chunk count.

Important:

- `total` means total **data chunks**, not total QR count.
- For parity chunks, the printed footer label is not authoritative.
  Use the parsed header.

---

## Step 4. Deduplicate and group

At this point, you should build a structure roughly like:

- all chunks for one `file_id`
- grouped by `group_index`
- separated into data and parity

You can safely deduplicate byte-identical chunk blobs.

A practical approach is:

- keep the first valid copy of each unique raw chunk blob
- ignore duplicate scans of the same QR
- preserve all non-duplicate chunks, even if you do not yet know whether they are enough

---

## Step 5. Reconstruct the logical data chunk stream

### Case A: no FEC

If there are only data chunks and no parity chunks:

1. ensure all data indexes from `0` to `total-1` are present
2. sort by `index`
3. concatenate payloads in order

The result is the complete `QFSC` blob.

### Case B: XOR FEC

For each group:

- expect up to `group_size` data chunks
- expect 1 parity chunk
- parity payload layout is:
  - 2-byte count
  - `count` × 2-byte original lengths
  - XOR parity bytes

Recovery rule:

- if exactly 1 data chunk is missing in a group, recover it by XORing
  the parity bytes with all present data payloads padded to `chunk_size`
- then trim the recovered payload to the original length indicated in the parity metadata

If 2 or more data chunks are missing in the same XOR group,
that group cannot be fully reconstructed from XOR alone.

### Case C: Reed-Solomon FEC

For each group:

- expect up to `group_size` data chunks
- expect `parity_count` parity chunks
- each parity chunk carries the same length-prefix metadata format,
  followed by one parity vector

Recovery rule:

- build the symbol vector column by column
- mark missing data and missing parity positions as erasures
- run RS erasure decoding
- fill in the missing data bytes
- trim recovered chunks to the original per-chunk lengths

A group can survive up to `parity_count` total erasures.
Those erasures may include missing parity chunks as well as missing data chunks.

---

## Step 6. Validate the reassembled transport blob

After concatenating data chunk payloads, you should have one `QFSC` transport blob.
It must begin with:

```text
QFSC
```

Then inspect:

- version
- mode
- flags

That tells you whether the payload is:

- clear
- password-encrypted
- public-key-encrypted
- signed

If the transport blob does not parse cleanly, the problem is still in chunk recovery,
Base45 decoding, or FEC reconstruction.

---

## Step 7. Recover clear, password, or public-key payloads

### Clear mode

If `mode = 0`:

- if not signed, the bytes after the header are the packed `QFSP` payload
- if signed, first verify the trailing Ed25519 signature, then strip it and extract the payload

### Password mode

If `mode = 1`:

You need:

- the passphrase
- the exact transport blob

Procedure:

1. read `salt` and `nonce`
2. derive the 32-byte key with Argon2id
3. use AES-256-GCM with the transport header as AAD
4. decrypt the ciphertext+tag
5. the output is the packed `QFSP` payload

If decryption fails, likely causes are:

- wrong password
- mutated chunk data
- incomplete reconstruction
- wrong AAD reconstruction due to malformed header parsing

### Public-key mode

If `mode = 2`:

You need:

- the recipient X25519 private key

Procedure:

1. read the recipient `key_id`
2. read `sealed_len`
3. read the `sealed` session-key box
4. use the recipient private key to open the sealed box
5. decrypt the ciphertext with AES-256-GCM using the session key
6. the output is the packed `QFSP` payload

If the provided private key does not correspond to the expected recipient key id,
recovery should stop.

---

## Step 8. Verify signatures when present

If the `signed` flag is set:

- the transport header contains the sender key id and full Ed25519 verify key
- the blob ends with a 64-byte signature

The signature covers the entire unsigned transport blob.

Manual verification flow:

1. split the trailing 64-byte signature
2. verify it using the embedded Ed25519 verify key
3. only then trust the claimed sender metadata

QRFS may also map the signer key id or fingerprint to a local address book entry,
but that mapping is convenience only. The cryptographic truth is the verify key.

---

## Step 9. Unpack `QFSP`

Once you have the inner packed payload, it should begin with:

```text
QFSP
```

Procedure:

1. parse version, metadata length, and payload length
2. parse the metadata JSON
3. extract the payload bytes
4. if `compressed = true`, zlib-decompress the payload bytes
5. write the resulting file bytes to disk

The metadata JSON currently tells you at least:

- original filename
- MIME type
- whether compression was used
- original size

---

## What helps but is not strictly required

These artifacts are useful, but not essential:

- the QRFS manifest JSON
- the PDF page footer labels
- page ordering information
- a QRFS installation

The hard requirements are the QR payload strings and enough valid chunks.

---

## Minimal recovery strategy by scenario

### Scenario 1: clear mode, no FEC

This is the easiest case.

Needed:

- all data chunks

Procedure:

- scan all QR
- Base45-decode
- parse chunks
- sort data chunks by `index`
- concatenate payloads
- parse `QFSC`
- extract clear payload
- parse `QFSP`
- unpack file

### Scenario 2: clear mode, FEC enabled

Needed:

- enough chunks to reconstruct all missing data chunks within FEC limits

Procedure:

- same as above, but group by FEC metadata first
- recover missing data with XOR or RS
- only then concatenate logical data chunk payloads

### Scenario 3: password mode

Needed:

- enough chunks to reconstruct the `QFSC` blob
- the correct password

Procedure:

- reconstruct chunk stream
- decrypt `QFSC`
- unpack `QFSP`

### Scenario 4: public-key mode

Needed:

- enough chunks to reconstruct the `QFSC` blob
- recipient private key

Procedure:

- reconstruct chunk stream
- open sealed session key
- decrypt `QFSC`
- unpack `QFSP`

---

## Failure modes and likely causes

### Base45 decode fails

Likely causes:

- scanner altered the text
- wrong payload copied
- a non-QRFS QR was included

### Chunk magics do not match

Likely causes:

- corrupted scan
- partial payload string
- wrong decoder path

### Multiple file IDs appear

Likely causes:

- mixed pages from different jobs
- stale scans from a previous recovery session

### Missing chunks remain after FEC

Likely causes:

- too many erasures in one FEC group
- parity chunks missing too
- bad chunk grouping logic in your recovery script

### Signature verification fails

Likely causes:

- wrong blob boundaries
- truncated or mutated payload
- wrong verify key extraction

### AES-GCM decryption fails

Likely causes:

- wrong password or wrong private key
- incorrect header reconstruction used as AAD
- corrupted ciphertext

### `QFSP` unpack fails

Likely causes:

- crypto layer output is wrong
- payload lengths were parsed incorrectly
- compression flag or zlib stage was mishandled

---

## Suggested long-term archival practice

For QRFS objects intended for long-term offline survivability, keep together:

- the printed QR pages
- a copy of `README.md`
- `docs/FORMAT.md`
- this `docs/MANUAL_RECOVERY.md`
- if possible, one machine-readable copy of the manifest JSON

For highly sensitive content, store decryption and identity material separately and intentionally.

---

## Practical recommendation

If you are building an independent recovery tool, implement recovery in this order:

1. Base45 decode
2. chunk parser for `QRC3`
3. no-FEC reconstruction
4. XOR reconstruction
5. `QFSC` clear mode
6. `QFSP` unpacking
7. password mode
8. public-key mode
9. signature verification
10. legacy `QRC1` and `QRC2` support if needed

That order gets you a working recovery path quickly while keeping the implementation understandable.

---

## Reference files in this repository

- `qrfs/core/utils.py`
- `qrfs/core/chunker.py`
- `qrfs/core/crypto_utils.py`
- `qrfs/core/packaging.py`
- `qrfs/core/qrdecode.py`

The QRFS implementation remains the reference behavior.
This guide is intended to make that behavior legible and reproducible.
