import base64
import hashlib
import io
import json
from datetime import datetime, timezone

import qrcode
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey

PUBLIC_KEY_FORMAT = 'qrfs-key-v1'
IDENTITY_CARD_FORMAT = 'qrfs-identity-card-v1'


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _b64_public_key_bytes(value: str) -> bytes:
    raw = base64.b64decode((value or '').strip())
    if len(raw) != 32:
        raise ValueError('Invalid public key: unexpected length.')
    return raw


def build_identity_card_dict(*,
                             display_name: str = '',
                             encryption_public_key_b64: str,
                             signing_public_key_b64: str,
                             created_at: str | None = None,
                             notes: str = '') -> dict:
    enc_raw = _b64_public_key_bytes(encryption_public_key_b64)
    sign_raw = _b64_public_key_bytes(signing_public_key_b64)
    display_name = (display_name or '').strip()
    notes = (notes or '').strip()
    return {
        'format': IDENTITY_CARD_FORMAT,
        'version': 1,
        'display_name': display_name,
        'created_at': created_at or utc_now_iso(),
        'encryption_public_key_b64': encryption_public_key_b64.strip(),
        'encryption_key_id': key_id_from_public_key(enc_raw).hex(),
        'encryption_fingerprint': hashlib.sha256(enc_raw).hexdigest(),
        'signing_public_key_b64': signing_public_key_b64.strip(),
        'signing_key_id': signing_key_id_from_verify_key(sign_raw).hex(),
        'signing_fingerprint': signing_fingerprint_from_verify_key(sign_raw),
        'notes': notes,
    }


def build_identity_card_payload(*,
                                display_name: str = '',
                                encryption_public_key_b64: str,
                                signing_public_key_b64: str,
                                created_at: str | None = None,
                                notes: str = '') -> str:
    payload = build_identity_card_dict(
        display_name=display_name,
        encryption_public_key_b64=encryption_public_key_b64,
        signing_public_key_b64=signing_public_key_b64,
        created_at=created_at,
        notes=notes,
    )
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'))


def parse_identity_card_input(value: str) -> dict:
    value = (value or '').strip()
    if not value:
        raise ValueError('Missing identity card.')
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError('Identity card non valida.') from exc
    if payload.get('format') != IDENTITY_CARD_FORMAT:
        raise ValueError('Format identity card non riconosciuto.')
    enc_b64 = (payload.get('encryption_public_key_b64') or '').strip()
    sign_b64 = (payload.get('signing_public_key_b64') or '').strip()
    if not enc_b64 or not sign_b64:
        raise ValueError('Incomplete identity card: missing public keys.')
    card = build_identity_card_dict(
        display_name=payload.get('display_name') or '',
        encryption_public_key_b64=enc_b64,
        signing_public_key_b64=sign_b64,
        created_at=payload.get('created_at') or utc_now_iso(),
        notes=payload.get('notes') or '',
    )
    return card



def normalize_public_key_input(value: str, expected_kind: str = "x25519") -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Missing public key.")
    if value.startswith("{"):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid public-key payload.") from exc
        fmt = payload.get("format")
        if fmt == IDENTITY_CARD_FORMAT:
            card = parse_identity_card_input(value)
            if expected_kind == 'x25519':
                return card['encryption_public_key_b64']
            if expected_kind == 'ed25519':
                return card['signing_public_key_b64']
            raise ValueError(f"Unexpected key type: expected {expected_kind}.")
        kind = payload.get("kind")
        public_key_b64 = (payload.get("public_key_b64") or "").strip()
        if fmt != PUBLIC_KEY_FORMAT:
            raise ValueError("Unrecognized key QR format.")
        if expected_kind and kind != expected_kind:
            raise ValueError(f"Unexpected key type: expected {expected_kind}, got {kind}.")
        if not public_key_b64:
            raise ValueError("Payload QR senza public_key_b64.")
        _b64_public_key_bytes(public_key_b64)
        return public_key_b64
    _b64_public_key_bytes(value)
    return value



def generate_key_materials() -> dict:
    enc_sk = PrivateKey.generate()
    enc_pk = enc_sk.public_key
    sign_sk = SigningKey.generate()
    sign_vk = sign_sk.verify_key

    enc_public_key_b64 = base64.b64encode(bytes(enc_pk)).decode('ascii')
    sign_public_key_b64 = base64.b64encode(bytes(sign_vk)).decode('ascii')
    enc_key_id = key_id_from_public_key(bytes(enc_pk)).hex()
    sign_key_id = signing_key_id_from_verify_key(bytes(sign_vk)).hex()
    enc_fp = hashlib.sha256(bytes(enc_pk)).hexdigest()
    sign_fp = signing_fingerprint_from_verify_key(bytes(sign_vk))

    encryption_qr_payload = build_public_key_qr_payload(
        kind='x25519',
        public_key_b64=enc_public_key_b64,
        key_id=enc_key_id,
        fingerprint=enc_fp,
    )
    signing_qr_payload = build_public_key_qr_payload(
        kind='ed25519',
        public_key_b64=sign_public_key_b64,
        key_id=sign_key_id,
        fingerprint=sign_fp,
    )
    identity_card_payload = build_identity_card_payload(
        encryption_public_key_b64=enc_public_key_b64,
        signing_public_key_b64=sign_public_key_b64,
    )

    return {
        'encryption_private_key_b64': base64.b64encode(bytes(enc_sk)).decode('ascii'),
        'encryption_public_key_b64': enc_public_key_b64,
        'encryption_public_key_id': enc_key_id,
        'encryption_public_key_fingerprint': enc_fp,
        'signing_private_key_b64': base64.b64encode(bytes(sign_sk)).decode('ascii'),
        'signing_public_key_b64': sign_public_key_b64,
        'signing_public_key_id': sign_key_id,
        'signing_public_key_fingerprint': sign_fp,
        'encryption_qr_payload': encryption_qr_payload,
        'signing_qr_payload': signing_qr_payload,
        'identity_card_payload': identity_card_payload,
        'encryption_qr_data_uri': qr_png_data_uri(encryption_qr_payload),
        'signing_qr_data_uri': qr_png_data_uri(signing_qr_payload),
        'identity_card_qr_data_uri': qr_png_data_uri(identity_card_payload),
        'encryption_fingerprint_qr_data_uri': qr_png_data_uri(enc_fp),
        'signing_fingerprint_qr_data_uri': qr_png_data_uri(sign_fp),
    }



def build_public_key_qr_payload(*, kind: str, public_key_b64: str, key_id: str, fingerprint: str) -> str:
    payload = {
        'format': PUBLIC_KEY_FORMAT,
        'kind': kind,
        'key_id': key_id,
        'fingerprint_sha256': fingerprint,
        'public_key_b64': public_key_b64,
    }
    return json.dumps(payload, separators=(',', ':'))



def qr_png_data_uri(payload: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    encoded = base64.b64encode(buf.getvalue()).decode('ascii')
    return f'data:image/png;base64,{encoded}'



def generate_keypair() -> dict:
    return generate_key_materials()



def key_id_from_public_key(public_key_bytes: bytes) -> bytes:
    return hashlib.sha256(public_key_bytes).digest()[:8]



def signing_key_id_from_verify_key(verify_key_bytes: bytes) -> bytes:
    return hashlib.sha256(verify_key_bytes).digest()[:8]



def signing_fingerprint_from_verify_key(verify_key_bytes: bytes) -> str:
    return hashlib.sha256(verify_key_bytes).hexdigest()



def parse_public_key_b64(value: str) -> PublicKey:
    raw = _b64_public_key_bytes(value)
    return PublicKey(raw)



def parse_private_key_b64(value: str) -> PrivateKey:
    raw = base64.b64decode(value.strip())
    if len(raw) != 32:
        raise ValueError('Invalid private key: unexpected length.')
    return PrivateKey(raw)



def parse_signing_private_key_b64(value: str) -> SigningKey:
    raw = base64.b64decode(value.strip())
    if len(raw) != 32:
        raise ValueError('Invalid signing private key: unexpected length.')
    return SigningKey(raw)
