# QRFS – QR Filesystem

QRFS is an experimental system to encode encrypted data into printable QR code pages.

It is NOT a traditional filesystem.

It is a:
> **physical, offline, encrypted data transport and storage system**

---

## 🧠 What QRFS Is

QRFS allows you to:

- take any file
- encrypt it securely
- split it into chunks
- encode it into QR codes
- print or display them
- reconstruct the file later from scans or photos

It works offline, including local encode/decode and the browser-based live scanner shipped in `qrfs/static/vendor/`.

---

## 🚀 Core Features

- Password-based encryption (Argon2 + AEAD)
- Public key encryption (X25519 / SealedBox)
- Digital signatures (Ed25519)
- Chunking system
- FEC (XOR and Reed-Solomon, with explicit parity QR)
- Multi-page PDF generation
- Scan & reconstruct from images

---

## ⚖️ What QRFS Is NOT

- Not a replacement for cloud storage
- Not efficient for large data
- Not a high-speed transfer system

---

## 🔥 Real Use Cases

### 1. Air-gapped data transfer
Move data between isolated systems without USB or network.

### 2. Field data exchange
Exchange data without connectivity using printed pages or phone images.

### 3. Physical encrypted archive
Store data in printed form, readable without digital infrastructure.

---

## 🧊 Long-term Archival / Time Capsule

QRFS can be used for **long-term data preservation**.

Concept:

- Store data on physical media (paper, metal, glass)
- Include:
  - human-readable explanation
  - decoding instructions
  - format specification
- Encode actual data using QRFS

This creates a **self-describing archive**.

Even if all software is lost, the data can be reconstructed.

---

## 🧠 Key Insight

QRFS separates:

- **data transport (physical)**
- **data security (cryptography)**

---

## 📦 Working with Multiple Files

QRFS operates on a single input file.

For multiple files or folders:

👉 Create a ZIP archive first, then encode it.

ZIP may optionally be password-protected as an additional layer.

---

## 🧩 FEC: XOR vs Reed-Solomon

QRFS can optionally add **extra parity QR codes** to improve recovery when some QR codes are missing or unreadable.

### XOR FEC

- adds **1 parity QR** for each group of `N` data QR
- can recover **at most 1 missing data chunk per group**
- simple, predictable, and easy to reason about

Example: with group size `5`, QRFS emits `5 data + 1 parity`.
If exactly one of those 5 data QR is missing, QRFS can reconstruct it.
If two data QR are missing from the same group, XOR is not enough.

### Reed-Solomon FEC

- adds `P` parity QR for each group of `N` data QR
- can recover up to `P` **known erasures per group**
- more flexible than XOR, but also denser and more demanding

Example: with group size `5` and parity `2`, QRFS emits `5 data + 2 parity`.
That group can survive up to 2 missing chunks in total inside the group.

### Important practical notes

- FEC helps with **missing or unreadable chunks**. It does **not** replace the QR code's own ECC level.
- Parity QR carry a small amount of extra metadata (chunk lengths), so they can be **slightly larger** than plain data QR.
- Dense presets plus FEC should always be tested on your **real printer / camera / scanner** path before relying on them.
- The internal **Testbench** page is useful for validating chunk loss scenarios before publishing or field use.

---

## ⚠️ Limitations

- Low data density compared to digital storage
- Requires reconstruction process
- Depends on image quality when scanning
- Physical media can degrade

---

## 🔐 Security Model

Security relies on:

- strong password (with Argon2)
- or public/private key cryptography
- authenticated encryption

---

## 🌍 Future Directions

- Better scanning UX
- Improved FEC strategies
- Standardization of QRFS format
- Physical medium optimization (metal, engraving, etc.)
- Time capsule edition

---

## 🧭 Philosophy

QRFS is not about replacing modern systems.

It is about:

> **having an alternative when modern systems are unavailable**

---

## 🛠 Installation (Termux)

See INSTALL_TERMUX.md

Runtime note: `python qrfs.py` starts QRFS in plain HTTP by default. On the same device use `http://127.0.0.1:5000`; from another device on the LAN use `http://<IP-del-dispositivo>:5000`. `python qrfs.py --debug` keeps Flask debug mode, while the default non-debug path uses Waitress when installed.

---

## 📜 License

QRFS is released under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

---

## 💬 Final Note

QRFS is a niche tool.

But in the right context, it enables something unique:
offline, encrypted, physical data transmission and storage.

---

<p align="center">
  <b>Made with ❤️ for freedom</b><br><br>
  <a href="https://github.com/flyingsurveyor">FlyingSurveyor</a> · Italy
</p>
