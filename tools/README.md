# QRFS Tools

This directory contains standalone developer and operational tools that are not
part of the main Flask application.

---

## `rescue.js` — Offline browser rescue tool

`rescue.js` is the standalone reference version of the browser-side rescue UI
logic. It implements Base45 decoding, QRFS chunk header parsing (QRC1/QRC2/QRC3),
and the live-camera / manual-input collection flow used on the `/rescue` page.

The same JavaScript is also inlined in `qrfs/templates/rescue.html`, which is
served by the Flask app. This standalone file exists as a reference copy so the
rescue logic can be embedded in a custom offline HTML page without running the
Python server.

**How to use it independently:**

1. Copy `rescue.js` into a directory alongside a copy of
   `qrfs/static/vendor/html5-qrcode-2.3.8.min.js`.
2. Create an HTML page that includes both scripts and provides the DOM elements
   expected by `rescue.js` (see `qrfs/templates/rescue.html` for the required
   element IDs).
3. Open the HTML page in any modern browser — no build step, no server required.

---

## `diagnose_pdf.py` — PDF decode diagnostic

`diagnose_pdf.py` is a command-line diagnostic tool for testing QRFS PDF decoding
outside of the web interface.

**Usage:**

```bash
python tools/diagnose_pdf.py /path/to/file.pdf [password]
```

It decodes all QR codes from the PDF, reconstructs the blob, and optionally
decrypts and unpacks the file if a password is provided. Useful for debugging
failed PDF round-trips.

**Requirements:** `poppler-utils` (`pdftoppm`/`pdfinfo`) must be installed.
