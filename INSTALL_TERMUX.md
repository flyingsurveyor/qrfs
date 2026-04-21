# Installation on Termux

## 1. System packages

```bash
pkg update && pkg upgrade
pkg install python clang libjpeg-turbo libpng zbar poppler
```

## 2. Install Python dependencies

```bash
cd ~/qr_filesystem_v14_fixed
pip install -r requirements.txt --break-system-packages
```

## 3. Start

```bash
python qrfs.py
```

By default QRFS starts in plain HTTP.
Use `python qrfs.py --debug` only when you explicitly want Flask debug mode.

Open on the same device: `http://127.0.0.1:5000`

Open from another device on the LAN: `http://<IP-del-dispositivo>:5000`

At first access the browser will warn about the self-signed certificate. This is expected; the certificate remains stable across reboots, so once trusted it stays the same.

## 4. Diagnostics

```bash
which pdftoppm           # should print a path
python -c "from pyzbar.pyzbar import decode; print('OK')"
```
