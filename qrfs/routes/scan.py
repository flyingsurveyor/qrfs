import json
import os
import secrets

from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file, jsonify

from ..core.utils import b45decode, b45encode, timestamp_slug
from ..core.crypto_utils import decrypt_file_payload_auto, inspect_crypto_blob
from ..core.packaging import unpack_file_payload
from ..core.qrdecode import decode_qr_bytes_from_images
from ..core.chunker import reconstruct_from_chunks, parse_chunk
from ..core.keystore import identity_exists, unlock_identity, get_public_identity_no_password
from ..core.address_book import find_contact_by_signer

scan_bp = Blueprint('scan', __name__, url_prefix='/scan')


def _pending_paths(temp_dir: str, token: str) -> tuple[str, str]:
    safe_token = ''.join(ch for ch in token if ch.isalnum())
    return (
        os.path.join(temp_dir, f'scan_{safe_token}.json'),
        os.path.join(temp_dir, f'scan_{safe_token}.bin'),
    )


def _save_pending_state(temp_dir: str, encrypted_blob: bytes, context: dict) -> str:
    token = secrets.token_hex(16)
    meta_path, blob_path = _pending_paths(temp_dir, token)
    with open(blob_path, 'wb') as f:
        f.write(encrypted_blob)
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(context, f, ensure_ascii=False)
    return token


def _load_pending_state(temp_dir: str, token: str) -> tuple[dict, bytes]:
    meta_path, blob_path = _pending_paths(temp_dir, token)
    if not (os.path.isfile(meta_path) and os.path.isfile(blob_path)):
        raise FileNotFoundError('Camera decode session not found or expired.')
    with open(meta_path, 'r', encoding='utf-8') as f:
        context = json.load(f)
    with open(blob_path, 'rb') as f:
        blob = f.read()
    return context, blob


def _clear_pending_state(temp_dir: str, token: str) -> None:
    for path in _pending_paths(temp_dir, token):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _enrich_signature_info(base_dir: str, my_identity: dict | None, signature_info: dict | None) -> dict | None:
    if not signature_info:
        return None
    enriched = dict(signature_info)
    if my_identity and signature_info.get('signer_fingerprint') == my_identity.get('signing_fingerprint'):
        enriched['trust_status'] = 'self'
        enriched['signer_label'] = my_identity.get('display_name') or 'Local identity'
        return enriched
    contact = find_contact_by_signer(
        base_dir,
        signer_key_id=signature_info.get('signer_key_id'),
        signer_fingerprint=signature_info.get('signer_fingerprint'),
    )
    if contact:
        enriched['trust_status'] = 'known_contact'
        enriched['signer_label'] = contact.get('name') or contact.get('display_name')
        enriched['contact_id'] = contact.get('id')
    else:
        enriched['trust_status'] = 'unknown'
    return enriched


def _render_decode_result(recovered: dict, output_name: str, file_id_hex: str | None,
                          encryption_mode: str, recipient_key_id: str | None,
                          signature_info: dict | None, fec_info: dict,
                          decode_stats: dict, qr_count: int):
    return render_template(
        'decode_result.html',
        original_name=recovered['filename'],
        output_name=output_name,
        mime_type=recovered['mime_type'],
        compressed=recovered['compressed'],
        qr_count=qr_count,
        file_id_hex=file_id_hex,
        encryption_mode=encryption_mode,
        recipient_key_id=recipient_key_id,
        signature_info=signature_info,
        fec_info=fec_info,
        decode_stats=decode_stats,
    )


def _decode_uploaded_qrfs_photo(photo_storage, temp_dir: str) -> tuple[list[str], dict]:
    from werkzeug.utils import secure_filename

    safe_name = secure_filename(photo_storage.filename or 'photo.jpg') or 'photo.jpg'
    temp_path = os.path.join(temp_dir, f"{timestamp_slug()}_{safe_name}")
    photo_storage.save(temp_path)
    try:
        raw_chunks, decode_stats = decode_qr_bytes_from_images([temp_path], return_stats=True)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    b45_chunks: list[str] = []
    seen: set[str] = set()
    for raw in raw_chunks:
        try:
            parse_chunk(raw)
        except Exception:
            continue
        encoded = b45encode(raw)
        if encoded in seen:
            continue
        seen.add(encoded)
        b45_chunks.append(encoded)
    return b45_chunks, decode_stats


@scan_bp.route('/photo_chunk', methods=['POST'])
def scan_photo_chunk():
    photo = request.files.get('photo')
    if not photo or not photo.filename:
        return jsonify({'ok': False, 'error': 'No photo provided.'}), 400

    try:
        chunks, decode_stats = _decode_uploaded_qrfs_photo(photo, current_app.config['TEMP_DIR'])
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Photo decode failed: {exc}'}), 500

    if not chunks:
        return jsonify({
            'ok': False,
            'error': 'No QRFS chunk found in the photo.',
            'stats': decode_stats,
        }), 200

    return jsonify({
        'ok': True,
        'chunks': chunks,
        'count': len(chunks),
        'stats': decode_stats,
    })


@scan_bp.route('/')
def scan_view():
    base_dir = current_app.config['BASE_DIR']
    return render_template(
        'scan.html',
        has_identity=identity_exists(base_dir),
        my_identity=get_public_identity_no_password(base_dir),
    )


@scan_bp.route('/submit', methods=['POST'])
def scan_submit():
    base_dir = current_app.config['BASE_DIR']
    temp_dir = current_app.config['TEMP_DIR']
    has_identity = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)
    action = request.form.get('action', 'scan').strip().lower()

    if action == 'cancel_pending':
        token = request.form.get('pending_token', '').strip()
        if token:
            _clear_pending_state(temp_dir, token)
        flash('Sblocco annullato.', 'info')
        return redirect(url_for('scan.scan_view'))

    if action == 'unlock':
        token = request.form.get('pending_token', '').strip()
        password = request.form.get('password', '').strip()
        private_key = request.form.get('private_key', '').strip()
        master_password = request.form.get('master_password', '').strip()
        use_identity = request.form.get('use_identity') == 'on'

        try:
            pending, encrypted_blob = _load_pending_state(temp_dir, token)
        except Exception as exc:
            flash(str(exc), 'error')
            return redirect(url_for('scan.scan_view'))

        if pending.get('mode') == 'pubkey' and use_identity and has_identity and master_password and not private_key:
            try:
                identity = unlock_identity(base_dir, master_password)
                private_key = identity['encryption_private_key_b64']
            except Exception as exc:
                return render_template(
                    'scan.html',
                    has_identity=has_identity,
                    my_identity=my_identity,
                    pending_decrypt=pending,
                    pending_token=token,
                    modal_error=f'Identity unlock: {exc}',
                )

        try:
            packed, encryption_mode, recipient_key_id, signature_info = decrypt_file_payload_auto(
                encrypted_blob,
                password=password if password else None,
                private_key_b64=private_key if private_key else None,
            )
            recovered = unpack_file_payload(packed)
        except Exception as exc:
            return render_template(
                'scan.html',
                has_identity=has_identity,
                my_identity=my_identity,
                pending_decrypt=pending,
                pending_token=token,
                modal_error=f'Decoding failed: {exc}',
            )

        output_name = f"restored_{timestamp_slug()}_{recovered['filename']}"
        output_path = os.path.join(current_app.config['OUTPUT_DIR'], output_name)
        with open(output_path, 'wb') as f:
            f.write(recovered['file_bytes'])

        _clear_pending_state(temp_dir, token)
        signature_info = _enrich_signature_info(base_dir, my_identity, signature_info)
        return _render_decode_result(
            recovered=recovered,
            output_name=output_name,
            file_id_hex=pending.get('file_id_hex'),
            encryption_mode=encryption_mode,
            recipient_key_id=recipient_key_id,
            signature_info=signature_info,
            fec_info=pending['fec_info'],
            decode_stats=pending['decode_stats'],
            qr_count=pending['qr_count'],
        )

    chunk_data_json = request.form.get('chunk_data', '').strip()
    if not chunk_data_json:
        flash('No chunks scanned.', 'error')
        return redirect(url_for('scan.scan_view'))

    try:
        b45_strings = json.loads(chunk_data_json)
    except Exception:
        flash('Dati chunk non validi.', 'error')
        return redirect(url_for('scan.scan_view'))

    chunk_payloads = []
    for s in b45_strings:
        try:
            raw = b45decode(s)
            chunk_payloads.append(raw)
        except Exception as e:
            flash(f'Base45 decode error: {e}', 'error')
            return redirect(url_for('scan.scan_view'))

    if not chunk_payloads:
        flash('No valid chunks.', 'error')
        return redirect(url_for('scan.scan_view'))

    try:
        encrypted_blob, fec_info = reconstruct_from_chunks(chunk_payloads)
        crypto_info = inspect_crypto_blob(encrypted_blob)
    except Exception as exc:
        flash(f'Decoding failed: {exc}', 'error')
        return redirect(url_for('scan.scan_view'))

    parsed_chunks = [parse_chunk(raw) for raw in chunk_payloads]
    file_id_hex = parsed_chunks[0].file_id.hex() if parsed_chunks else None
    decode_stats = {
        'pages_total': 0,
        'pages_with_hits': 0,
        'qr_total_seen': len(chunk_payloads),
        'qr_unique': len(chunk_payloads),
        'duplicates_discarded': 0,
        'preprocess_attempts': 0,
        'cells_scanned': 0,
        'decoder_backend': 'camera',
        'pdf_backend': 'none',
    }

    if crypto_info['mode'] == 'clear':
        try:
            packed, encryption_mode, recipient_key_id, signature_info = decrypt_file_payload_auto(encrypted_blob)
            recovered = unpack_file_payload(packed)
        except Exception as exc:
            flash(f'Decoding failed: {exc}', 'error')
            return redirect(url_for('scan.scan_view'))

        output_name = f"restored_{timestamp_slug()}_{recovered['filename']}"
        output_path = os.path.join(current_app.config['OUTPUT_DIR'], output_name)
        with open(output_path, 'wb') as f:
            f.write(recovered['file_bytes'])

        signature_info = _enrich_signature_info(base_dir, my_identity, signature_info)
        return _render_decode_result(
            recovered=recovered,
            output_name=output_name,
            file_id_hex=file_id_hex,
            encryption_mode=encryption_mode,
            recipient_key_id=recipient_key_id,
            signature_info=signature_info,
            fec_info=fec_info,
            decode_stats=decode_stats,
            qr_count=len(parsed_chunks),
        )

    pending_context = {
        'mode': crypto_info['mode'],
        'signed': crypto_info['signed'],
        'recipient_key_id': crypto_info.get('recipient_key_id'),
        'qr_count': len(parsed_chunks),
        'file_id_hex': file_id_hex,
        'fec_info': fec_info,
        'decode_stats': decode_stats,
    }
    token = _save_pending_state(temp_dir, encrypted_blob, pending_context)

    return render_template(
        'scan.html',
        has_identity=has_identity,
        my_identity=my_identity,
        pending_decrypt=pending_context,
        pending_token=token,
    )


@scan_bp.route('/download/<path:filename>')
def download_restored(filename: str):
    path = os.path.join(current_app.config['OUTPUT_DIR'], filename)
    if not os.path.isfile(path):
        flash('File not found.', 'error')
        return redirect(url_for('scan.scan_view'))
    return send_file(path, as_attachment=True)
