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

## 🛠 Installation

QRFS starts in plain HTTP by default.

- On the same device: `http://127.0.0.1:5000`
- From another device on the same LAN: `http://<device-ip>:5000`

Run `python qrfs.py --debug` only if you explicitly want Flask debug mode.
The default non-debug path uses Waitress when installed.

### Raspberry Pi / Debian / Ubuntu

#### 1. Install system packages

```bash
sudo apt update
sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  poppler-utils \
  libzbar0
```

If `pip install -r requirements.txt` needs to compile native packages, install these optional build dependencies too:

```bash
sudo apt install -y \
  build-essential \
  python3-dev \
  pkg-config \
  libjpeg-dev \
  zlib1g-dev \
  libpng-dev \
  libffi-dev \
  libssl-dev \
  cargo
```

#### 2. Clone the repository

```bash
git clone https://github.com/flyingsurveyor/qrfs.git
cd qrfs
```

#### 3. Create a virtual environment and install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

#### 4. Start QRFS

```bash
python qrfs.py
```

### Termux

#### 1. Install system packages

```bash
pkg update
pkg upgrade -y
pkg install -y \
  git \
  python \
  zbar \
  poppler \
  libjpeg-turbo \
  libpng
```

If `pip install -r requirements.txt` needs to compile native packages, install these optional build dependencies too:

```bash
pkg install -y \
  clang \
  make \
  pkg-config \
  ndk-sysroot \
  rust
```

#### 2. Clone the repository

```bash
git clone https://github.com/flyingsurveyor/qrfs.git
cd qrfs
```

#### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

#### 4. Start QRFS

```bash
python qrfs.py
```

### Quick dependency check

```bash
which pdftoppm
python -c "from pyzbar.pyzbar import decode; print('OK')"
```

If `pdftoppm` is found and the Python command prints `OK`, the main decoding dependencies are in place.

---

## 🌍 Future Directions

QRFS is still experimental, but its direction is becoming clearer.

The goal is not to turn it into a generic storage system or a novelty QR project.

The real direction is to make QRFS more reliable, more self-describing, and more useful in degraded, offline, hostile, or infrastructure-poor environments.

Possible future directions include:

- **Better scanning UX**  
  Faster and more reliable recovery from photos and scans, with clearer feedback about missing, duplicated, or damaged chunks.

- **Improved FEC strategies**  
  Smarter redundancy profiles, better real-world recovery behavior, and stronger resilience to partial page loss or poor image quality.

- **Standardization of the QRFS format**  
  A documented, versioned, implementation-independent format that can be decoded and reconstructed without relying on a single codebase.

- **Physical medium optimization**  
  Better support for paper, low-quality printers, difficult lighting, and more durable media such as metal, engraving, or other long-life physical substrates.

- **Time capsule / archival edition**  
  A more conservative and self-describing archival mode designed for long-term preservation, with human-readable recovery guidance and format documentation.

- **Paranoid Mode for politically harsh environments**  
  A minimal-disclosure mode that reduces metadata leakage, avoids unnecessary identifiers, and makes physical transport safer in hostile conditions.

- **Transport to and from Reticulum networks**  
  Using QRFS as a physical bridge for disconnected or delayed networks: exporting payloads from Reticulum, carrying them physically, and reinjecting them later.

- **Paper computing / executable capsules**  
  Exploring whether small scripts, bootstrap tools, configurations, and operational payloads can travel physically on paper as signed, inspectable, self-describing QRFS bundles.

- **Field-ready operational profiles**  
  Clear presets such as archive, rugged field, balanced, or dense mode, so QRFS can be tuned for real-world use instead of only lab conditions.

In the long term, QRFS may evolve from a simple encrypted QR transport tool into something broader:

> **a physical carrier for data, instructions, and minimal capabilities across disconnected worlds**

---

## 🧭 Philosophy

QRFS is not about replacing modern systems.

It is about:

> **having an alternative when modern systems are unavailable**

---

## 📜 License

QRFS is released under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

---

<p align="center">
  <b>Made with ❤️ for freedom</b><br><br>
  <a href="https://github.com/flyingsurveyor">FlyingSurveyor</a> · Italy
</p>
