from datetime import datetime


def human_bytes(size: int) -> str:
    units = ['B', 'KB', 'MB', 'GB']
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f'{value:.1f} {unit}'
        value /= 1024.0
    return f'{size} B'


def timestamp_slug() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S_%f')


def percent_str(value: float) -> str:
    return f"{value * 100:.1f}%"


# ── Base45 codec (RFC 9285) ──────────────────────────────────────

_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_INV = {c: i for i, c in enumerate(_B45)}


def b45encode(data: bytes) -> str:
    """Encode bytes to base45 string (alphanumeric-safe for QR codes)."""
    out = []
    for i in range(0, len(data) - 1, 2):
        val = data[i] * 256 + data[i + 1]
        c, val = divmod(val, 2025)  # 45*45
        b, a = divmod(val, 45)
        out.append(_B45[a])
        out.append(_B45[b])
        out.append(_B45[c])
    if len(data) % 2 == 1:
        b, a = divmod(data[-1], 45)
        out.append(_B45[a])
        out.append(_B45[b])
    return ''.join(out)


def b45decode(s: str) -> bytes:
    """Decode base45 string back to bytes."""
    out = []
    for i in range(0, len(s) - 2, 3):
        a = _B45_INV[s[i]]
        b = _B45_INV[s[i + 1]]
        c = _B45_INV[s[i + 2]]
        val = a + b * 45 + c * 2025
        out.append(val >> 8)
        out.append(val & 0xFF)
    if len(s) % 3 == 2:
        a = _B45_INV[s[-2]]
        b = _B45_INV[s[-1]]
        out.append(a + b * 45)
    return bytes(out)
