"""Persistent identity keystore for QRFS.

Stores the user's own keypairs (encryption X25519 + signing Ed25519)
encrypted with a master password using Argon2id + AES-256-GCM.
Also supports public identity cards and encrypted identity backups.
"""

import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from nacl.pwhash import argon2id

from .key_utils import build_identity_card_dict, parse_private_key_b64, parse_signing_private_key_b64

IDENTITY_FILE = 'identity.enc'
PUBLIC_IDENTITY_FILE = 'identity_public.json'
IDENTITY_MAGIC = b'QFSI'
IDENTITY_VERSION = 2
IDENTITY_BACKUP_FORMAT = 'qrfs-identity-backup-v1'
IDENTITY_RECOVERY_FORMAT = 'qrfs-identity-recovery-sheet-v1'
NONCE_LEN = 12
SALT_LEN = 16
MIN_MASTER_PASSWORD_LEN = 14
DEFAULT_OPSLIMIT = 3
DEFAULT_MEMLIMIT = 64 * 1024 * 1024


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _identity_path(base_dir: str) -> str:
    data_dir = os.path.join(base_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, IDENTITY_FILE)



def _public_path(base_dir: str) -> str:
    data_dir = os.path.join(base_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, PUBLIC_IDENTITY_FILE)



def _validate_master_password(password: str) -> None:
    if len(password or '') < MIN_MASTER_PASSWORD_LEN:
        raise ValueError(f'Master password must be at least {MIN_MASTER_PASSWORD_LEN} characters.')



def _derive_key(password: str, salt: bytes, *, opslimit: int = DEFAULT_OPSLIMIT,
                memlimit: int = DEFAULT_MEMLIMIT) -> bytes:
    return argon2id.kdf(
        32,
        password.encode('utf-8'),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )



def identity_exists(base_dir: str) -> bool:
    return os.path.isfile(_identity_path(base_dir))



def _build_identity(*, display_name: str, enc_sk: PrivateKey, sign_sk: SigningKey) -> dict:
    enc_pk = enc_sk.public_key
    sign_vk = sign_sk.verify_key
    return {
        'display_name': (display_name or '').strip(),
        'created_at': _utc_now_iso(),
        'encryption_private_key_b64': base64.b64encode(bytes(enc_sk)).decode('ascii'),
        'encryption_public_key_b64': base64.b64encode(bytes(enc_pk)).decode('ascii'),
        'signing_private_key_b64': base64.b64encode(bytes(sign_sk)).decode('ascii'),
        'signing_public_key_b64': base64.b64encode(bytes(sign_vk)).decode('ascii'),
    }



def generate_identity(base_dir: str, master_password: str, display_name: str = '') -> dict:
    _validate_master_password(master_password)
    enc_sk = PrivateKey.generate()
    sign_sk = SigningKey.generate()
    identity = _build_identity(display_name=display_name, enc_sk=enc_sk, sign_sk=sign_sk)
    _save_identity(base_dir, identity, master_password)
    return _public_info(identity)



def unlock_identity(base_dir: str, master_password: str) -> dict:
    path = _identity_path(base_dir)
    if not os.path.isfile(path):
        raise ValueError('No saved identity. Generate or import one first.')

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 4 + 1 + SALT_LEN + NONCE_LEN:
        raise ValueError('Corrupted identity file.')
    if data[:4] != IDENTITY_MAGIC:
        raise ValueError('Corrupted identity file.')

    version = data[4]
    if version != IDENTITY_VERSION:
        raise ValueError(f'Unsupported identity format: v{version}.')

    salt = data[5:5 + SALT_LEN]
    nonce = data[5 + SALT_LEN:5 + SALT_LEN + NONCE_LEN]
    ciphertext = data[5 + SALT_LEN + NONCE_LEN:]
    key = _derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, IDENTITY_MAGIC + bytes([version]))
    except Exception as exc:
        raise ValueError('Wrong master password.') from exc

    identity = json.loads(plaintext.decode('utf-8'))
    if 'display_name' not in identity:
        identity['display_name'] = ''
    if 'created_at' not in identity:
        identity['created_at'] = _utc_now_iso()
    return identity



def get_public_identity(base_dir: str, master_password: str) -> dict:
    return _public_info(unlock_identity(base_dir, master_password))



def _normalize_public_info(public_info: dict | None) -> dict | None:
    if not public_info:
        return None
    info = dict(public_info)
    enc_b64 = info.get('encryption_public_key_b64') or info.get('encryption_public_key')
    sign_b64 = info.get('signing_public_key_b64') or info.get('signing_public_key')
    if not enc_b64 or not sign_b64:
        raise ValueError('Incomplete public identity card.')
    normalized = build_identity_card_dict(
        display_name=info.get('display_name') or '',
        encryption_public_key_b64=enc_b64,
        signing_public_key_b64=sign_b64,
        created_at=info.get('created_at') or _utc_now_iso(),
        notes=info.get('notes') or '',
    )
    normalized['has_private_keys'] = True
    return normalized



def get_public_identity_no_password(base_dir: str) -> dict | None:
    pub_path = _public_path(base_dir)
    if not os.path.isfile(pub_path):
        return None
    with open(pub_path, 'r', encoding='utf-8') as f:
        return _normalize_public_info(json.load(f))



def _save_identity(base_dir: str, identity: dict, master_password: str):
    _validate_master_password(master_password)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(identity, ensure_ascii=False, sort_keys=True).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, IDENTITY_MAGIC + bytes([IDENTITY_VERSION]))

    with open(_identity_path(base_dir), 'wb') as f:
        f.write(IDENTITY_MAGIC + bytes([IDENTITY_VERSION]) + salt + nonce + ciphertext)

    with open(_public_path(base_dir), 'w', encoding='utf-8') as f:
        json.dump(_public_info(identity), f, ensure_ascii=False, indent=2)



def _public_info(identity: dict) -> dict:
    public_info = build_identity_card_dict(
        display_name=identity.get('display_name') or '',
        encryption_public_key_b64=identity['encryption_public_key_b64'],
        signing_public_key_b64=identity['signing_public_key_b64'],
        created_at=identity.get('created_at') or _utc_now_iso(),
        notes=identity.get('notes') or '',
    )
    public_info['has_private_keys'] = True
    return public_info



def export_identity_card(base_dir: str) -> dict:
    public = get_public_identity_no_password(base_dir)
    if not public:
        raise ValueError('No public identity available.')
    return public



def export_identity_backup(base_dir: str, master_password: str,
                           backup_password: str | None = None) -> bytes:
    identity = unlock_identity(base_dir, master_password)
    password = backup_password or master_password
    _validate_master_password(password)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(identity, ensure_ascii=False, sort_keys=True).encode('utf-8')
    aad = IDENTITY_BACKUP_FORMAT.encode('utf-8') + b':1'
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    payload = {
        'format': IDENTITY_BACKUP_FORMAT,
        'version': 1,
        'created_at': _utc_now_iso(),
        'kdf': 'argon2id',
        'opslimit': DEFAULT_OPSLIMIT,
        'memlimit': DEFAULT_MEMLIMIT,
        'salt_b64': base64.b64encode(salt).decode('ascii'),
        'nonce_b64': base64.b64encode(nonce).decode('ascii'),
        'ciphertext_b64': base64.b64encode(ciphertext).decode('ascii'),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')



def _load_backup_payload(backup_blob: bytes | str) -> dict:
    if isinstance(backup_blob, bytes):
        backup_blob = backup_blob.decode('utf-8')
    try:
        payload = json.loads((backup_blob or '').strip())
    except Exception as exc:
        raise ValueError('Invalid identity backup.') from exc
    if payload.get('format') != IDENTITY_BACKUP_FORMAT or payload.get('version') != 1:
        raise ValueError('Unrecognized identity backup format.')
    return payload



def import_identity_backup(base_dir: str, backup_blob: bytes | str, backup_password: str,
                           new_master_password: str | None = None, overwrite: bool = False) -> dict:
    if identity_exists(base_dir) and not overwrite:
        raise ValueError('A local identity already exists. Enable overwrite to import the backup.')
    payload = _load_backup_payload(backup_blob)
    salt = base64.b64decode(payload['salt_b64'])
    nonce = base64.b64decode(payload['nonce_b64'])
    ciphertext = base64.b64decode(payload['ciphertext_b64'])
    opslimit = int(payload.get('opslimit') or DEFAULT_OPSLIMIT)
    memlimit = int(payload.get('memlimit') or DEFAULT_MEMLIMIT)
    key = _derive_key(backup_password, salt, opslimit=opslimit, memlimit=memlimit)
    aesgcm = AESGCM(key)
    aad = IDENTITY_BACKUP_FORMAT.encode('utf-8') + b':1'
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError('Wrong backup password or corrupted backup.') from exc
    identity = json.loads(plaintext.decode('utf-8'))
    save_password = new_master_password or backup_password
    _save_identity(base_dir, identity, save_password)
    return _public_info(identity)



def export_identity_recovery_sheet(base_dir: str, master_password: str) -> dict:
    identity = unlock_identity(base_dir, master_password)
    public_info = _public_info(identity)
    return {
        'format': IDENTITY_RECOVERY_FORMAT,
        'version': 1,
        'created_at': _utc_now_iso(),
        'warning': 'Contains cleartext private keys. Store offline securely.',
        'display_name': identity.get('display_name') or '',
        'identity_card': public_info,
        'encryption_private_key_b64': identity['encryption_private_key_b64'],
        'signing_private_key_b64': identity['signing_private_key_b64'],
    }


def import_identity_from_private_keys(base_dir: str, *,
                                      encryption_private_key_b64: str,
                                      signing_private_key_b64: str,
                                      master_password: str,
                                      display_name: str = '',
                                      overwrite: bool = False) -> dict:
    if identity_exists(base_dir) and not overwrite:
        raise ValueError("A local identity already exists. Enable overwrite to import the private keys.")
    _validate_master_password(master_password)
    enc_sk = parse_private_key_b64((encryption_private_key_b64 or '').strip())
    sign_sk = parse_signing_private_key_b64((signing_private_key_b64 or '').strip())
    identity = _build_identity(display_name=(display_name or '').strip(), enc_sk=enc_sk, sign_sk=sign_sk)
    _save_identity(base_dir, identity, master_password)
    return _public_info(identity)


def import_identity_recovery_sheet(base_dir: str, recovery_blob: bytes | str, *,
                                   master_password: str, overwrite: bool = False) -> dict:
    if isinstance(recovery_blob, bytes):
        recovery_blob = recovery_blob.decode('utf-8')
    try:
        payload = json.loads((recovery_blob or '').strip())
    except Exception as exc:
        raise ValueError('Invalid recovery sheet.') from exc
    if payload.get('format') != IDENTITY_RECOVERY_FORMAT or payload.get('version') != 1:
        raise ValueError('Unrecognized recovery-sheet format.')
    display_name = (payload.get('display_name') or '').strip()
    card = payload.get('identity_card') or {}
    if not display_name and isinstance(card, dict):
        display_name = (card.get('display_name') or '').strip()
    return import_identity_from_private_keys(
        base_dir,
        encryption_private_key_b64=(payload.get('encryption_private_key_b64') or '').strip(),
        signing_private_key_b64=(payload.get('signing_private_key_b64') or '').strip(),
        master_password=master_password,
        display_name=display_name,
        overwrite=overwrite,
    )


def delete_identity(base_dir: str):
    for path in (_identity_path(base_dir), _public_path(base_dir)):
        if os.path.isfile(path):
            os.remove(path)
