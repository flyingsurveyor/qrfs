import json
import os
import time
from typing import Any

from .key_utils import (
    normalize_public_key_input,
    parse_identity_card_input,
    parse_public_key_b64,
    key_id_from_public_key,
    signing_key_id_from_verify_key,
    signing_fingerprint_from_verify_key,
)


ADDRESS_BOOK_FILENAME = 'address_book.json'


def address_book_path(base_dir: str) -> str:
    data_dir = os.path.join(base_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, ADDRESS_BOOK_FILENAME)



def _normalize_contact(item: dict[str, Any]) -> dict[str, Any]:
    contact = dict(item)
    enc_b64 = (contact.get('encryption_public_key_b64') or contact.get('public_key_b64') or '').strip()
    if enc_b64:
        enc_raw = bytes(parse_public_key_b64(enc_b64))
        contact['encryption_public_key_b64'] = enc_b64
        contact['public_key_b64'] = enc_b64
        contact['encryption_key_id'] = contact.get('encryption_key_id') or contact.get('key_id') or key_id_from_public_key(enc_raw).hex()
        contact['key_id'] = contact['encryption_key_id']
        contact['encryption_fingerprint'] = contact.get('encryption_fingerprint') or contact.get('fingerprint_sha256')
        if not contact.get('encryption_fingerprint'):
            import hashlib
            contact['encryption_fingerprint'] = hashlib.sha256(enc_raw).hexdigest()
        contact['fingerprint_sha256'] = contact['encryption_fingerprint']

    sign_b64 = (contact.get('signing_public_key_b64') or '').strip()
    if sign_b64:
        import base64
        sign_raw = base64.b64decode(sign_b64)
        if len(sign_raw) == 32:
            contact['signing_public_key_b64'] = sign_b64
            contact['signing_key_id'] = contact.get('signing_key_id') or signing_key_id_from_verify_key(sign_raw).hex()
            contact['signing_fingerprint'] = contact.get('signing_fingerprint') or signing_fingerprint_from_verify_key(sign_raw)

    contact['name'] = (contact.get('name') or '').strip()
    contact['display_name'] = (contact.get('display_name') or contact['name']).strip()
    contact['note'] = (contact.get('note') or '').strip()
    contact['id'] = contact.get('id') or contact.get('key_id') or contact.get('signing_key_id')
    return contact



def load_contacts(base_dir: str) -> list[dict[str, Any]]:
    path = address_book_path(base_dir)
    if not os.path.isfile(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, list):
        return []
    contacts: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            contacts.append(_normalize_contact(item))
        except Exception:
            continue
    contacts.sort(key=lambda item: ((item.get('name') or '').lower(), item.get('created_at') or 0))
    return contacts



def save_contacts(base_dir: str, contacts: list[dict[str, Any]]) -> None:
    path = address_book_path(base_dir)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(contacts, f, ensure_ascii=False, indent=2)



def add_contact(base_dir: str, *, name: str, public_key_input: str, note: str = '') -> dict[str, Any]:
    contacts = load_contacts(base_dir)
    raw_input = (public_key_input or '').strip()
    if not raw_input:
        raise ValueError('Missing public key or identity card.')

    note = (note or '').strip()
    is_identity_card = raw_input.startswith('{') and 'qrfs-identity-card-v1' in raw_input
    now = int(time.time())

    if is_identity_card:
        card = parse_identity_card_input(raw_input)
        display_name = (name or '').strip() or (card.get('display_name') or '').strip()
        if not display_name:
            raise ValueError('Missing contact name.')
        contact = {
            'id': card['encryption_key_id'],
            'name': display_name,
            'display_name': card.get('display_name') or display_name,
            'encryption_public_key_b64': card['encryption_public_key_b64'],
            'public_key_b64': card['encryption_public_key_b64'],
            'encryption_key_id': card['encryption_key_id'],
            'key_id': card['encryption_key_id'],
            'encryption_fingerprint': card['encryption_fingerprint'],
            'fingerprint_sha256': card['encryption_fingerprint'],
            'signing_public_key_b64': card['signing_public_key_b64'],
            'signing_key_id': card['signing_key_id'],
            'signing_fingerprint': card['signing_fingerprint'],
            'identity_card_format': card['format'],
            'identity_created_at': card.get('created_at'),
            'note': note,
            'created_at': now,
            'updated_at': now,
        }
    else:
        public_key_b64 = normalize_public_key_input(raw_input, expected_kind='x25519')
        public_key = parse_public_key_b64(public_key_b64)
        raw = bytes(public_key)
        import hashlib
        fingerprint = hashlib.sha256(raw).hexdigest()
        key_id = key_id_from_public_key(raw).hex()
        display_name = (name or '').strip()
        if not display_name:
            raise ValueError('Missing contact name.')
        contact = {
            'id': key_id,
            'name': display_name,
            'display_name': display_name,
            'encryption_public_key_b64': public_key_b64,
            'public_key_b64': public_key_b64,
            'encryption_key_id': key_id,
            'key_id': key_id,
            'encryption_fingerprint': fingerprint,
            'fingerprint_sha256': fingerprint,
            'note': note,
            'created_at': now,
            'updated_at': now,
        }

    existing = next((item for item in contacts if item.get('id') == contact['id'] or item.get('encryption_public_key_b64') == contact['encryption_public_key_b64']), None)
    if existing:
        existing.update(contact)
        existing['created_at'] = existing.get('created_at') or now
        existing['updated_at'] = now
        save_contacts(base_dir, contacts)
        return _normalize_contact(existing)

    contacts.append(contact)
    save_contacts(base_dir, contacts)
    return _normalize_contact(contact)



def delete_contact(base_dir: str, contact_id: str) -> bool:
    contacts = load_contacts(base_dir)
    new_contacts = [item for item in contacts if item.get('id') != contact_id]
    if len(new_contacts) == len(contacts):
        return False
    save_contacts(base_dir, new_contacts)
    return True



def get_contact(base_dir: str, contact_id: str) -> dict[str, Any] | None:
    for item in load_contacts(base_dir):
        if item.get('id') == contact_id:
            return item
    return None



def find_contact_by_signer(base_dir: str, *, signer_key_id: str | None = None,
                           signer_fingerprint: str | None = None) -> dict[str, Any] | None:
    signer_key_id = (signer_key_id or '').strip().lower()
    signer_fingerprint = (signer_fingerprint or '').strip().lower()
    for item in load_contacts(base_dir):
        if signer_key_id and (item.get('signing_key_id') or '').lower() == signer_key_id:
            return item
        if signer_fingerprint and (item.get('signing_fingerprint') or '').lower() == signer_fingerprint:
            return item
    return None
