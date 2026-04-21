import io
import math
import os
import zipfile
from typing import Callable, List, Optional
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from PIL import Image, ImageDraw, ImageFont
import qrcode
from .chunker import Chunk

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 10 * mm
HEADER_H = 12 * mm
FOOTER_H = 8 * mm
COLS = 5
ROWS = 6
PER_PAGE = COLS * ROWS
CELL_W = (PAGE_WIDTH - 2 * MARGIN) / COLS
CELL_H = (PAGE_HEIGHT - MARGIN - HEADER_H - FOOTER_H - MARGIN) / ROWS
PNG_SCALE = 3
FONT = ImageFont.load_default()

ECC_MAP = {
    'L': qrcode.constants.ERROR_CORRECT_L,
    'M': qrcode.constants.ERROR_CORRECT_M,
    'Q': qrcode.constants.ERROR_CORRECT_Q,
    'H': qrcode.constants.ERROR_CORRECT_H,
}


def _header_label(display_label: Optional[str], original_filename: str) -> str:
    label = (display_label or '').strip()
    if label:
        return label
    name = os.path.basename(original_filename or '').strip()
    stem, ext = os.path.splitext(name)
    ext = ext.lstrip('.').strip()
    return ext.upper() if ext else 'BINARY'


def _chunk_to_qr_image(chunk: Chunk, ecc_level: str = 'M'):
    from .utils import b45encode
    ecc = ECC_MAP.get(ecc_level.upper(), qrcode.constants.ERROR_CORRECT_M)
    qr = qrcode.QRCode(
        version=None,
        error_correction=ecc,
        box_size=3,
        border=2,
    )
    encoded = b45encode(chunk.to_bytes())
    qr.add_data(encoded, optimize=0)
    qr.make(fit=True)
    return qr.make_image(fill_color='black', back_color='white').convert('RGB')


def _interleave_page(chunks_on_page: list) -> list:
    n = len(chunks_on_page)
    if n <= 1:
        return list(chunks_on_page)
    stride = 7 if n >= 7 else 3
    result = [None] * n
    slot = 0
    for chunk in chunks_on_page:
        result[slot] = chunk
        slot = (slot + stride) % n
        while result[slot] is not None and any(r is None for r in result):
            slot = (slot + 1) % n
    return result


def build_qr_pdf(chunks: List[Chunk], output_path: str, original_filename: str,
                 ecc_level: str = 'M',
                 display_label: Optional[str] = None,
                 progress_callback: Optional[Callable[[int, int], None]] = None):
    c = canvas.Canvas(output_path, pagesize=A4)
    total_pages = math.ceil(len(chunks) / PER_PAGE)
    short_id = chunks[0].file_id.hex()[:12] if chunks else 'empty'
    header_label = _header_label(display_label, original_filename)

    for page_index in range(total_pages):
        page_chunks = chunks[page_index * PER_PAGE:(page_index + 1) * PER_PAGE]
        page_chunks = _interleave_page(page_chunks)
        c.setFont('Helvetica', 9)
        c.drawString(MARGIN, PAGE_HEIGHT - MARGIN,
                     f'ECC ({ecc_level.upper()}) | page {page_index + 1}/{total_pages}')
        c.setFont('Helvetica-Bold', 11)
        c.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - MARGIN,
                          f'QR Filesystem | {header_label} | ID {short_id}')

        for idx, chunk in enumerate(page_chunks):
            row = idx // COLS
            col = idx % COLS
            x = MARGIN + col * CELL_W
            y = PAGE_HEIGHT - MARGIN - HEADER_H - (row + 1) * CELL_H
            qr_img = _chunk_to_qr_image(chunk, ecc_level)
            bio = io.BytesIO()
            qr_img.save(bio, format='PNG')
            bio.seek(0)
            img_reader = ImageReader(bio)

            img_size = min(CELL_W, CELL_H) - 8
            img_x = x + (CELL_W - img_size) / 2
            img_y = y + (CELL_H - img_size) / 2 + 5
            c.drawImage(img_reader, img_x, img_y, width=img_size, height=img_size,
                        preserveAspectRatio=True, mask='auto')
            c.setFont('Helvetica', 7)
            c.drawCentredString(x + CELL_W / 2, y + 3, f'{chunk.index + 1}/{chunk.total}')

        c.setFont('Helvetica', 8)
        c.drawString(MARGIN, MARGIN / 2,
                     'Print in high quality for best results. Decoding supports PDF files or page images.')
        c.showPage()
        if progress_callback:
            progress_callback(page_index + 1, total_pages)

    c.save()


def _draw_text(draw: ImageDraw.ImageDraw, xy, text: str):
    draw.text(xy, text, fill='black', font=FONT)


def build_qr_page_images(chunks: List[Chunk], original_filename: str,
                         ecc_level: str = 'M',
                         display_label: Optional[str] = None,
                         progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Image.Image]:
    total_pages = math.ceil(len(chunks) / PER_PAGE)
    short_id = chunks[0].file_id.hex()[:12] if chunks else 'empty'
    header_label = _header_label(display_label, original_filename)
    page_w_px = int((PAGE_WIDTH / 72.0) * PNG_SCALE * 72)
    page_h_px = int((PAGE_HEIGHT / 72.0) * PNG_SCALE * 72)
    margin_px = int((MARGIN / 72.0) * PNG_SCALE * 72)
    header_px = int((HEADER_H / 72.0) * PNG_SCALE * 72)
    cell_w_px = int((page_w_px - 2 * margin_px) / COLS)
    cell_h_px = int((page_h_px - margin_px - header_px
                     - int((FOOTER_H / 72.0) * PNG_SCALE * 72) - margin_px) / ROWS)

    pages: List[Image.Image] = []
    for page_index in range(total_pages):
        page = Image.new('RGB', (page_w_px, page_h_px), 'white')
        draw = ImageDraw.Draw(page)
        _draw_text(draw, (margin_px, margin_px // 2),
                   f'ECC ({ecc_level.upper()}) | page {page_index + 1}/{total_pages}')
        right_text = f'QR Filesystem | {header_label} | ID {short_id}'
        right_bbox = draw.textbbox((0, 0), right_text, font=FONT)
        right_w = right_bbox[2] - right_bbox[0]
        _draw_text(draw, (page_w_px - margin_px - right_w, margin_px // 2), right_text)
        page_chunks = chunks[page_index * PER_PAGE:(page_index + 1) * PER_PAGE]
        page_chunks = _interleave_page(page_chunks)
        for idx, chunk in enumerate(page_chunks):
            row = idx // COLS
            col = idx % COLS
            x = margin_px + col * cell_w_px
            y = margin_px + header_px + row * cell_h_px
            qr_img = _chunk_to_qr_image(chunk, ecc_level)
            qr_size = min(cell_w_px, cell_h_px) - 24
            qr_img = qr_img.resize((qr_size, qr_size))
            page.paste(qr_img, (x + (cell_w_px - qr_size) // 2, y + 8))
            label = f'{chunk.index + 1}/{chunk.total}'
            _draw_text(draw, (x + cell_w_px // 2 - 18, y + cell_h_px - 18), label)
        _draw_text(draw, (margin_px, page_h_px - margin_px),
                   'Print in high quality for best results. Decoding supports PDF files or page images.')
        pages.append(page)
        if progress_callback:
            progress_callback(page_index + 1, total_pages)
    return pages


def build_png_zip(chunks: List[Chunk], output_zip_path: str, original_filename: str,
                  ecc_level: str = 'M',
                  display_label: Optional[str] = None,
                  progress_callback: Optional[Callable[[int, int], None]] = None) -> None:
    pages = build_qr_page_images(chunks, original_filename, ecc_level, display_label=display_label, progress_callback=progress_callback)
    stem = os.path.splitext(os.path.basename(output_zip_path))[0]
    with zipfile.ZipFile(output_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for idx, page in enumerate(pages, start=1):
            bio = io.BytesIO()
            page.save(bio, format='PNG', optimize=True)
            bio.seek(0)
            zf.writestr(f'{stem}_page_{idx:03d}.png', bio.read())
