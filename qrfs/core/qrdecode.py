"""QR Filesystem – decoder module (v14).

Decodes QR codes one by one using the known 5x6 grid from pdfgen.py.

PDF pipeline:
  1. Render ONE page at a time via pdftoppm to a temp PNG file.
  2. Open with PIL, crop each of the 30 grid cells.
  3. Decode each small crop with zbar.
  4. Free page, move to next.

Image pipeline:
  Downscale if needed, apply proportional grid, crop cells.

QR data is base45-encoded (alphanumeric mode, ~3% overhead vs raw binary).

Dependencies: PIL, pyzbar.
External: pdftoppm (poppler) for PDF.
"""

from __future__ import annotations

import gc
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PIL import Image, ImageOps, ImageFilter
from pyzbar.pyzbar import decode as zbar_decode


# ── Encoder grid layout (mirrors pdfgen.py) ───────────────────────
_MM = 72.0 / 25.4
_MARGIN_PT   = 10 * _MM
_HEADER_H_PT = 12 * _MM
_FOOTER_H_PT =  8 * _MM
_PAGE_W_PT   = 595.28
_PAGE_H_PT   = 841.89
_COLS, _ROWS = 5, 6
_CELL_W_PT = (_PAGE_W_PT - 2 * _MARGIN_PT) / _COLS
_CELL_H_PT = (_PAGE_H_PT - _MARGIN_PT - _HEADER_H_PT
              - _FOOTER_H_PT - _MARGIN_PT) / _ROWS


@dataclass
class DecodeStats:
    pages_total: int = 0
    pages_with_hits: int = 0
    qr_total_seen: int = 0
    qr_unique: int = 0
    duplicates_discarded: int = 0
    preprocess_attempts: int = 0
    cells_scanned: int = 0
    decoder_backend: str = "zbar"
    pdf_backend: str = "none"


# ── Helpers ───────────────────────────────────────────────────────

def _dedupe_extend(output: List[bytes], seen: set,
                   candidates: List[bytes], stats: DecodeStats) -> int:
    added = 0
    for item in candidates:
        if not item:
            continue
        stats.qr_total_seen += 1
        if item in seen:
            stats.duplicates_discarded += 1
            continue
        seen.add(item)
        output.append(item)
        stats.qr_unique += 1
        added += 1
    return added


def _zbar(img: Image.Image) -> List[bytes]:
    """Decode QR codes from an image. Handles base45, legacy raw, and text QRs."""
    from .utils import b45decode
    results = []
    for o in zbar_decode(img):
        if o.type != "QRCODE":
            continue
        raw = o.data
        # Try base45 → QRFS chunk
        try:
            text = raw.decode('ascii')
            decoded = b45decode(text)
            if decoded[:4] in (b'QRC1', b'QRC2', b'QRC3'):
                results.append(decoded)
                continue
        except Exception:
            pass
        # Raw binary QRFS (legacy)
        if raw[:4] in (b'QRC1', b'QRC2', b'QRC3'):
            results.append(raw)
            continue
        # Non-QRFS QR (public key, text, etc)
        results.append(raw)
    return results


def _decode_cell(cell: Image.Image, stats: DecodeStats) -> List[bytes]:
    """Decode a single small cell crop with preprocessing variants."""
    stats.preprocess_attempts += 1
    r = _zbar(cell)
    if r:
        return r

    gray = ImageOps.grayscale(cell)
    auto = ImageOps.autocontrast(gray)

    stats.preprocess_attempts += 1
    r = _zbar(auto)
    if r:
        return r

    stats.preprocess_attempts += 1
    r = _zbar(auto.filter(ImageFilter.SHARPEN))
    if r:
        return r

    for thr in (100, 128, 160, 190):
        bw = auto.point(lambda p, t=thr: 255 if p > t else 0)
        stats.preprocess_attempts += 1
        r = _zbar(bw)
        if r:
            return r

    for scale in (2.0, 3.0):
        w, h = auto.size
        big = auto.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        stats.preprocess_attempts += 1
        r = _zbar(big)
        del big
        if r:
            return r

    return []


# ── Grid cell positions ──────────────────────────────────────────

def _grid_cells_px(dpi: int) -> List[Tuple[int, int, int, int]]:
    """30 cells as (x, y, w, h) in pixels at given DPI."""
    s = dpi / 72.0
    cells = []
    for row in range(_ROWS):
        for col in range(_COLS):
            x = int((_MARGIN_PT + col * _CELL_W_PT) * s)
            y = int((_MARGIN_PT + _HEADER_H_PT + row * _CELL_H_PT) * s)
            w = int(_CELL_W_PT * s)
            h = int(_CELL_H_PT * s)
            cells.append((x, y, w, h))
    return cells


# ── PDF helpers ──────────────────────────────────────────────────

def _pdf_page_count(pdf_path: str) -> int:
    try:
        r = subprocess.run(
            ["pdfinfo", pdf_path],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            if line.startswith("Pages:"):
                return int(line.split(":", 1)[1].strip())
    except Exception:
        pass
    return 1


def _render_page_to_file(pdf_path: str, page_1based: int,
                         dpi: int, out_dir: str) -> Optional[str]:
    """Render one PDF page to a temp PNG file via pdftoppm.

    Returns path to PNG or None on failure.
    """
    out_prefix = os.path.join(out_dir, "page")
    try:
        subprocess.run(
            ["pdftoppm", "-png", "-r", str(dpi),
             "-f", str(page_1based), "-l", str(page_1based),
             pdf_path, out_prefix],
            check=True, capture_output=True, timeout=30,
        )
        pngs = sorted(f for f in os.listdir(out_dir) if f.endswith(".png"))
        return os.path.join(out_dir, pngs[0]) if pngs else None
    except Exception:
        return None


# ── Process one page: load, crop cells, decode ───────────────────

def _process_page_image(page_img: Image.Image,
                        cells: List[Tuple[int, int, int, int]],
                        found: List[bytes], seen: set,
                        stats: DecodeStats) -> bool:
    """Crop each grid cell and decode individually."""
    pw, ph = page_img.size
    had_hit = False

    for (cx, cy, cw, ch) in cells:
        x2 = min(cx + cw, pw)
        y2 = min(cy + ch, ph)
        if cx >= pw or cy >= ph or x2 <= cx or y2 <= cy:
            continue

        crop = page_img.crop((cx, cy, x2, y2))
        stats.cells_scanned += 1
        results = _decode_cell(crop, stats)
        n = _dedupe_extend(found, seen, results, stats)
        if n:
            had_hit = True
        del crop

    return had_hit


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════

def decode_qr_bytes_from_pdf(pdf_path: str, dpi: int = 150,
                             return_stats: bool = False, progress_callback=None):
    """Decode QR codes from a multi-page PDF.

    Renders each page ONCE to a temp PNG via pdftoppm, then crops
    the 30 grid cells in PIL. Much faster than 30 separate pdftoppm calls.

    At 150 DPI a page is ~1240x1753 px (~6 MB). Each cell crop is ~200 KB.
    """
    if not shutil.which("pdftoppm"):
        raise RuntimeError(
            "pdftoppm non trovato. Installa poppler: pkg install poppler"
        )

    page_count = _pdf_page_count(pdf_path)
    cells = _grid_cells_px(dpi)

    chunks: List[bytes] = []
    seen: set = set()
    stats = DecodeStats(pages_total=page_count, pdf_backend="pdftoppm")

    for page_1 in range(1, page_count + 1):
        tmp_dir = tempfile.mkdtemp(prefix="qrfs_")
        try:
            png_path = _render_page_to_file(pdf_path, page_1, dpi, tmp_dir)
            if png_path is None:
                continue

            page_img = Image.open(png_path).convert("RGB")
            page_img.load()
            # Delete temp file immediately — pixels are in memory now
            os.remove(png_path)

            had_hit = _process_page_image(page_img, cells, chunks, seen, stats)
            if had_hit:
                stats.pages_with_hits += 1

            del page_img
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if progress_callback:
            try:
                progress_callback(page_1, page_count)
            except Exception:
                pass
        gc.collect()

    return (chunks, stats.__dict__) if return_stats else chunks


def decode_qr_bytes_from_images(image_paths: List[str],
                                return_stats: bool = False, progress_callback=None):
    """Decode QR codes from image files (photos, scans, PNG/JPG/TIFF/BMP).

    Supports any format PIL can open. Downscales large images.
    Applies proportional 5x6 grid matching the pdfgen layout.
    """
    chunks: List[bytes] = []
    seen: set = set()
    stats = DecodeStats(pages_total=len(image_paths))

    total_images = len(image_paths)

    for idx, path in enumerate(image_paths, start=1):
        image = Image.open(path).convert("RGB")
        pw, ph = image.size

        # Downscale large images (phone photos etc)
        max_long = 2000
        if max(pw, ph) > max_long:
            ratio = max_long / max(pw, ph)
            image = image.resize(
                (int(pw * ratio), int(ph * ratio)), Image.LANCZOS
            )
            pw, ph = image.size

        # Proportional grid matching pdfgen layout
        cx_r = _MARGIN_PT / _PAGE_W_PT
        cy_r = (_MARGIN_PT + _HEADER_H_PT) / _PAGE_H_PT
        cw_r = _CELL_W_PT / _PAGE_W_PT
        ch_r = _CELL_H_PT / _PAGE_H_PT

        cells = []
        for row in range(_ROWS):
            for col in range(_COLS):
                x = int((cx_r + col * cw_r) * pw)
                y = int((cy_r + row * ch_r) * ph)
                w = int(cw_r * pw)
                h = int(ch_r * ph)
                cells.append((x, y, w, h))

        had_hit = _process_page_image(image, cells, chunks, seen, stats)

        # Fallback: try whole image as single QR
        if not had_hit:
            stats.cells_scanned += 1
            results = _decode_cell(image, stats)
            n = _dedupe_extend(chunks, seen, results, stats)
            if n:
                had_hit = True

        if had_hit:
            stats.pages_with_hits += 1
        del image
        if progress_callback:
            try:
                progress_callback(idx, total_images)
            except Exception:
                pass
        gc.collect()

    return (chunks, stats.__dict__) if return_stats else chunks
