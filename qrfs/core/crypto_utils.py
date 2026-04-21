"""QRFS Cryptographic utilities — Version 5.

KDF:     Argon2id (PyNaCl/libsodium)
Cipher:  AES-256-GCM with authenticated headers (AAD)
KeyEx:   X25519 via NaCl SealedBox
Signing: Ed25519

Wire format (QFSC v5):
  Clear mode:
    "QFSC" ver(5) mode(0) flags(1) [signer(40)] payload [signature(64)]
  Password mode:
    "QFSC" ver(5) mode(1) flags(1) salt(16) nonce(12) [signer(40)] ciphertext+tag [signature(64)]
  Pubkey mode:
    "QFSC" ver(5) mode(2) flags(1) key_id(8) sealed_len(2) nonce(12) [signer(40)] sealed ciphertext+tag [signature(64)]

If FLAG_SIGNED is set, the Ed25519 signature is appended at end and covers the whole
unsigned transport blob (header + encrypted payload). AES-GCM additionally authenticates
all transport headers through AAD.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import SealedBox
from nacl.signing import VerifyKey
from nacl.pwhash import argon2id

from .key_utils import (
    parse_public_key_b64,
    parse_private_key_b64,
    key_id_from_public_key,
    parse_signing_private_key_b64,
    signing_key_id_from_verify_key,
    signing_fingerprint_from_verify_key,
)

MAGIC = b'QFSC'
VERSION = 5
SALT_LEN = 16
NONCE_LEN = 12
SIGNATURE_LEN = 64
MODE_CLEAR = 0
MODE_PASSWORD = 1
MODE_PUBKEY = 2
FLAG_SIGNED = 0x01
MIN_PASSWORD_LEN = 14
ARGON2_OPSLIMIT = 3
ARGON2_MEMLIMIT = 64 * 1024 * 1024


def _derive_key(password: str, salt: bytes) -> bytes:
    return argon2id.kdf(
        32,
        password.encode('utf-8'),
        salt,
        opslimit=ARGON2_OPSLIMIT,
        memlimit=ARGON2_MEMLIMIT,
    )



def _validate_password(password: str) -> None:
    if len(password or '') < MIN_PASSWORD_LEN:
        raise ValueError(f'Password minimum {MIN_PASSWORD_LEN} characters.')



def _signature_metadata_from_verify_key(verify_key: bytes) -> bytes:
    return signing_key_id_from_verify_key(verify_key) + verify_key



def _sign_blob(unsigned_blob: bytes, sender_signing_private_key_b64: str | None) -> tuple[bytes, dict | None]:
    if not sender_signing_private_key_b64:
        return unsigned_blob, None
    signing_key = parse_signing_private_key_b64(sender_signing_private_key_b64)
    signature = signing_key.sign(unsigned_blob).signature
    verify_key = bytes(signing_key.verify_key)
    return unsigned_blob + signature, {
        'signer_key_id': signing_key_id_from_verify_key(verify_key).hex(),
        'signer_fingerprint': signing_fingerprint_from_verify_key(verify_key),
    }



def encrypt_file_payload_clear(payload: bytes,
                               sender_signing_private_key_b64: str | None = None) -> bytes:
    flags = FLAG_SIGNED if sender_signing_private_key_b64 else 0
    header = MAGIC + struct.pack('>BBB', VERSION, MODE_CLEAR, flags)
    if sender_signing_private_key_b64:
        signing_key = parse_signing_private_key_b64(sender_signing_private_key_b64)
        header += _signature_metadata_from_verify_key(bytes(signing_key.verify_key))
    return _sign_blob(header + payload, sender_signing_private_key_b64)[0]



def encrypt_file_payload_password(payload: bytes, password: str,
                                  sender_signing_private_key_b64: str | None = None) -> bytes:
    _validate_password(password)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    flags = FLAG_SIGNED if sender_signing_private_key_b64 else 0
    header = MAGIC + struct.pack('>BBB', VERSION, MODE_PASSWORD, flags) + salt + nonce
    if sender_signing_private_key_b64:
        signing_key = parse_signing_private_key_b64(sender_signing_private_key_b64)
        header += _signature_metadata_from_verify_key(bytes(signing_key.verify_key))
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, header)
    return _sign_blob(header + ciphertext, sender_signing_private_key_b64)[0]



def encrypt_file_payload_pubkey(payload: bytes, recipient_public_key_b64: str,
                                sender_signing_private_key_b64: str | None = None) -> bytes:
    recipient_pk = parse_public_key_b64(recipient_public_key_b64)
    session_key = os.urandom(32)
    nonce = os.urandom(NONCE_LEN)
    sealed = SealedBox(recipient_pk).encrypt(session_key)
    recipient_key_id = key_id_from_public_key(bytes(recipient_pk))
    flags = FLAG_SIGNED if sender_signing_private_key_b64 else 0
    header = (
        MAGIC
        + struct.pack('>BBB', VERSION, MODE_PUBKEY, flags)
        + recipient_key_id
        + struct.pack('>H', len(sealed))
        + nonce
    )
    if sender_signing_private_key_b64:
        signing_key = parse_signing_private_key_b64(sender_signing_private_key_b64)
        header += _signature_metadata_from_verify_key(bytes(signing_key.verify_key))
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, payload, header)
    return _sign_blob(header + sealed + ciphertext, sender_signing_private_key_b64)[0]



def encrypt_file_payload(payload: bytes, password: str) -> bytes:
    return encrypt_file_payload_password(payload, password)



def _verify_signed_blob(blob: bytes, verify_key_bytes: bytes) -> tuple[dict, bytes]:
    if len(blob) < SIGNATURE_LEN:
        raise ValueError('Signed blob too short.')
    signed_part = blob[:-SIGNATURE_LEN]
    signature = blob[-SIGNATURE_LEN:]
    verify_key = VerifyKey(verify_key_bytes)
    try:
        verify_key.verify(signed_part, signature)
    except Exception as exc:
        raise ValueError('Digital signature non valida.') from exc
    return {
        'verified': True,
        'signer_key_id': signing_key_id_from_verify_key(verify_key_bytes).hex(),
        'signer_fingerprint': signing_fingerprint_from_verify_key(verify_key_bytes),
    }, signed_part



def _signature_verify_key_from_header(blob: bytes) -> bytes:
    mode = blob[5]
    offset = 7
    if mode == MODE_PASSWORD:
        offset += SALT_LEN + NONCE_LEN
    elif mode == MODE_PUBKEY:
        offset += 8 + 2 + NONCE_LEN
    elif mode != MODE_CLEAR:
        raise ValueError(f'Unsupported encryption mode: {mode}')
    return blob[offset + 8:offset + 40]


def _split_signed_or_unsigned(blob: bytes) -> tuple[int, int, dict | None, bytes]:
    if blob[:4] != MAGIC or len(blob) < 7:
        raise ValueError('Invalid transport blob.')
    version = blob[4]
    if version != VERSION:
        raise ValueError(f'Unsupported cryptographic version: {version}')
    flags = blob[6]
    signature_info = None
    signed_or_unsigned = blob
    if flags & FLAG_SIGNED:
        verify_key_bytes = _signature_verify_key_from_header(blob)
        signature_info, signed_or_unsigned = _verify_signed_blob(blob, verify_key_bytes)
    return version, flags, signature_info, signed_or_unsigned



def decrypt_file_payload_password(blob: bytes, password: str) -> tuple[bytes, dict | None]:
    _validate_password(password)
    version, flags, signature_info, signed_or_unsigned = _split_signed_or_unsigned(blob)
    if signed_or_unsigned[5] != MODE_PASSWORD:
        raise ValueError('The payload does not use password mode.')
    offset = 7
    salt = signed_or_unsigned[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = signed_or_unsigned[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    if flags & FLAG_SIGNED:
        offset += 40
    header = signed_or_unsigned[:offset]
    ciphertext = signed_or_unsigned[offset:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        payload = aesgcm.decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise ValueError('Wrong password or corrupted data.') from exc
    return payload, signature_info



def decrypt_file_payload_pubkey(blob: bytes, private_key_b64: str) -> tuple[bytes, str, dict | None]:
    version, flags, signature_info, signed_or_unsigned = _split_signed_or_unsigned(blob)
    if signed_or_unsigned[5] != MODE_PUBKEY:
        raise ValueError('The payload does not use public-key mode.')
    offset = 7
    recipient_key_id = signed_or_unsigned[offset:offset + 8]
    offset += 8
    sealed_len = struct.unpack('>H', signed_or_unsigned[offset:offset + 2])[0]
    offset += 2
    nonce = signed_or_unsigned[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    if flags & FLAG_SIGNED:
        offset += 40
    header = signed_or_unsigned[:offset]
    sealed = signed_or_unsigned[offset:offset + sealed_len]
    ciphertext = signed_or_unsigned[offset + sealed_len:]

    priv = parse_private_key_b64(private_key_b64)
    actual_id = key_id_from_public_key(bytes(priv.public_key))
    if actual_id != recipient_key_id:
        raise ValueError('The provided private key does not match the expected recipient.')
    try:
        session_key = SealedBox(priv).decrypt(sealed)
    except Exception as exc:
        raise ValueError("Unable to open the recipient's sealed box.") from exc
    aesgcm = AESGCM(session_key)
    try:
        payload = aesgcm.decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise ValueError('Decryption failed: corrupted data or wrong key.') from exc
    return payload, actual_id.hex(), signature_info



def decrypt_file_payload_clear(blob: bytes) -> tuple[bytes, dict | None]:
    version, flags, signature_info, signed_or_unsigned = _split_signed_or_unsigned(blob)
    if signed_or_unsigned[5] != MODE_CLEAR:
        raise ValueError('The payload does not use cleartext mode.')
    offset = 7
    if flags & FLAG_SIGNED:
        offset += 40
    return signed_or_unsigned[offset:], signature_info



def inspect_crypto_blob(blob: bytes) -> dict:
    if blob[:4] != MAGIC or len(blob) < 7:
        raise ValueError('Invalid transport blob.')
    version = blob[4]
    if version != VERSION:
        raise ValueError(f'Unsupported cryptographic version: {version}')
    mode = blob[5]
    flags = blob[6]
    result = {
        'version': version,
        'mode': 'unknown',
        'signed': bool(flags & FLAG_SIGNED),
        'recipient_key_id': None,
    }
    if mode == MODE_CLEAR:
        result['mode'] = 'clear'
        return result
    if mode == MODE_PASSWORD:
        result['mode'] = 'password'
        return result
    if mode == MODE_PUBKEY:
        result['mode'] = 'pubkey'
        if len(blob) >= 15:
            result['recipient_key_id'] = blob[7:15].hex()
        return result
    raise ValueError(f'Unsupported encryption mode: {mode}')



def detect_encryption_mode(blob: bytes) -> str:
    return inspect_crypto_blob(blob)['mode']



def decrypt_file_payload_auto(blob: bytes, password: str | None = None,
                              private_key_b64: str | None = None) -> tuple[bytes, str, str | None, dict | None]:
    mode = detect_encryption_mode(blob)
    if mode == 'clear':
        payload, signature_info = decrypt_file_payload_clear(blob)
        return payload, mode, None, signature_info
    if mode == 'password':
        if not password:
            raise ValueError('This payload requires a password.')
        payload, signature_info = decrypt_file_payload_password(blob, password)
        return payload, mode, None, signature_info
    if not private_key_b64:
        raise ValueError('This payload requires a private key.')
    payload, recipient_key_id, signature_info = decrypt_file_payload_pubkey(blob, private_key_b64)
    return payload, mode, recipient_key_id, signature_info
