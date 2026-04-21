from flask import Blueprint, current_app, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from ..core.crypto_utils import decrypt_file_payload_auto, inspect_crypto_blob
from ..core.packaging import unpack_file_payload
from ..core.qrdecode import decode_qr_bytes_from_pdf, decode_qr_bytes_from_images
from ..core.chunker import reconstruct_from_chunks, parse_chunk
from ..core.utils import timestamp_slug, b45decode, b45encode
from ..core.keystore import identity_exists, unlock_identity, get_public_identity_no_password
from ..core.address_book import find_contact_by_signer
import json
import mimetypes
import os
import secrets
import shutil
import tempfile
import threading
import time
import uuid


decode_bp = Blueprint('decode', __name__, url_prefix='/decode')

DECODE_TASKS = {}
DECODE_TASKS_LOCK = threading.Lock()
DECODE_TASK_TTL_SECONDS = 60 * 60 * 12


def _cleanup_old_decode_tasks() -> None:
    cutoff = time.time() - DECODE_TASK_TTL_SECONDS
    with DECODE_TASKS_LOCK:
        stale = [task_id for task_id, task in DECODE_TASKS.items() if task.get('updated_at', 0) < cutoff]
        for task_id in stale:
            DECODE_TASKS.pop(task_id, None)


def _create_decode_task() -> str:
    _cleanup_old_decode_tasks()
    task_id = uuid.uuid4().hex
    with DECODE_TASKS_LOCK:
        DECODE_TASKS[task_id] = {
            'task_id': task_id,
            'status': 'queued',
            'percent': 0,
            'stage': 'Queued',
            'message': 'Preparing decode request…',
            'created_at': time.time(),
            'updated_at': time.time(),
            'result': None,
            'pending_token': None,
            'error': None,
        }
    return task_id


def _update_decode_task(task_id: str, **fields) -> None:
    with DECODE_TASKS_LOCK:
        task = DECODE_TASKS.get(task_id)
        if not task:
            return
        task.update(fields)
        task['updated_at'] = time.time()


def _get_decode_task(task_id: str):
    with DECODE_TASKS_LOCK:
        task = DECODE_TASKS.get(task_id)
        return dict(task) if task else None


def _build_empty_decode_stats() -> dict:
    return {
        'pages_total': 0,
        'pages_with_hits': 0,
        'qr_total_seen': 0,
        'qr_unique': 0,
        'duplicates_discarded': 0,
        'preprocess_attempts': 0,
        'cells_scanned': 0,
        'decoder_backend': 'zbar',
        'pdf_backend': 'none',
        'manual_qr_added': 0,
    }


def _merge_decode_stats(base: dict, extra: dict) -> dict:
    for key in ('pages_total', 'pages_with_hits', 'qr_total_seen', 'qr_unique',
                'duplicates_discarded', 'preprocess_attempts', 'cells_scanned', 'manual_qr_added'):
        base[key] = base.get(key, 0) + extra.get(key, 0)
    if extra.get('pdf_backend') and extra.get('pdf_backend') != 'none':
        base['pdf_backend'] = extra.get('pdf_backend')
    return base


def _decode_uploaded_qrfs_photo(photo_storage, config: dict) -> tuple[list[str], dict]:
    safe_name = secure_filename(photo_storage.filename or 'photo.jpg') or 'photo.jpg'
    temp_path = os.path.join(config['TEMP_DIR'], f'{timestamp_slug()}_{safe_name}')
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


@decode_bp.route('/rescue/photo_chunk', methods=['POST'])
def rescue_photo_chunk():
    photo = request.files.get('photo')
    if not photo or not photo.filename:
        return jsonify({'ok': False, 'error': 'No photo provided.'}), 400

    try:
        chunks, decode_stats = _decode_uploaded_qrfs_photo(photo, current_app.config)
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


def _decode_progress_updater(task_id: str, stage: str, start_percent: int, end_percent: int, noun: str):
    def _callback(done: int, total: int):
        if total <= 0:
            pct = start_percent
            message = f'{stage}…'
        else:
            pct = start_percent + int((done / total) * (end_percent - start_percent))
            message = f'{stage}: {noun} {done}/{total}…'
        _update_decode_task(
            task_id,
            status='running',
            percent=min(max(pct, start_percent), end_percent),
            stage=stage,
            message=message,
        )
    return _callback


def _collect_chunk_payloads_from_files(scan_pdf, scan_images, config: dict) -> tuple[list[bytes], dict]:
    decode_stats = _build_empty_decode_stats()
    chunk_payloads: list[bytes] = []

    if scan_pdf and scan_pdf.filename:
        safe_name = secure_filename(scan_pdf.filename) or 'scan.pdf'
        temp_path = os.path.join(config['TEMP_DIR'], f'{timestamp_slug()}_{safe_name}')
        scan_pdf.save(temp_path)
        try:
            pdf_chunks, pdf_stats = decode_qr_bytes_from_pdf(temp_path, return_stats=True)
            chunk_payloads.extend(pdf_chunks)
            decode_stats = _merge_decode_stats(decode_stats, pdf_stats)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    for image in scan_images:
        if not image or not image.filename:
            continue
        safe_name = secure_filename(image.filename)
        temp_path = os.path.join(config['TEMP_DIR'], f'{timestamp_slug()}_{safe_name}')
        image.save(temp_path)
        try:
            img_chunks, img_stats = decode_qr_bytes_from_images([temp_path], return_stats=True)
            chunk_payloads.extend(img_chunks)
            decode_stats = _merge_decode_stats(decode_stats, img_stats)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return chunk_payloads, decode_stats


def _collect_chunk_payloads_from_paths(scan_pdf_path: str | None, scan_image_paths: list[str], task_id: str | None = None) -> tuple[list[bytes], dict]:
    decode_stats = _build_empty_decode_stats()
    chunk_payloads: list[bytes] = []

    if scan_pdf_path and os.path.isfile(scan_pdf_path):
        if task_id:
            _update_decode_task(task_id, status='running', percent=12, stage='PDF scan', message='Reading QR pages from the uploaded PDF…')
        pdf_chunks, pdf_stats = decode_qr_bytes_from_pdf(
            scan_pdf_path,
            return_stats=True,
            progress_callback=_decode_progress_updater(task_id, 'PDF scan', 12, 68, 'page') if task_id else None,
        )
        chunk_payloads.extend(pdf_chunks)
        decode_stats = _merge_decode_stats(decode_stats, pdf_stats)

    if scan_image_paths:
        image_start = 18 if not scan_pdf_path else 72
        image_end = 78 if not scan_pdf_path else 86
        if task_id:
            _update_decode_task(task_id, status='running', percent=image_start, stage='Image scan', message='Reading QR pages from uploaded images…')
        img_chunks, img_stats = decode_qr_bytes_from_images(
            scan_image_paths,
            return_stats=True,
            progress_callback=_decode_progress_updater(task_id, 'Image scan', image_start, image_end, 'image') if task_id else None,
        )
        chunk_payloads.extend(img_chunks)
        decode_stats = _merge_decode_stats(decode_stats, img_stats)

    return chunk_payloads, decode_stats


def _collect_manual_chunks(raw_text: str) -> tuple[list[bytes], dict]:
    stats = _build_empty_decode_stats()
    payloads: list[bytes] = []
    seen: set[bytes] = set()
    errors: list[str] = []
    lines = [line.rstrip('\r') for line in raw_text.splitlines() if line.strip()]
    for idx, line in enumerate(lines, start=1):
        candidate = line.strip('\ufeff')
        try:
            decoded = b45decode(candidate)
        except Exception as exc:
            errors.append(f'Line {idx}: invalid Base45 ({exc}).')
            continue
        if not decoded.startswith((b'QRC1', b'QRC2', b'QRC3')):
            errors.append(f'Line {idx}: the text does not look like a valid QRFS chunk.')
            continue
        if decoded in seen:
            stats['duplicates_discarded'] += 1
            continue
        seen.add(decoded)
        payloads.append(decoded)
        stats['manual_qr_added'] += 1
        stats['qr_total_seen'] += 1
        stats['qr_unique'] += 1
    if errors:
        raise ValueError(' '.join(errors[:5]))
    return payloads, stats


def _pending_paths(temp_dir: str, token: str) -> tuple[str, str]:
    safe_token = ''.join(ch for ch in token if ch.isalnum())
    return (
        os.path.join(temp_dir, f'decode_{safe_token}.json'),
        os.path.join(temp_dir, f'decode_{safe_token}.bin'),
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
        raise FileNotFoundError('Decode session not found or expired.')
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


def _decode_result_context(recovered: dict, output_name: str, file_id_hex: str | None,
                           encryption_mode: str, recipient_key_id: str | None,
                           signature_info: dict | None, fec_info: dict,
                           decode_stats: dict, qr_count: int) -> dict:
    return {
        'original_name': recovered['filename'],
        'output_name': output_name,
        'mime_type': recovered['mime_type'],
        'compressed': recovered['compressed'],
        'qr_count': qr_count,
        'file_id_hex': file_id_hex,
        'encryption_mode': encryption_mode,
        'recipient_key_id': recipient_key_id,
        'signature_info': signature_info,
        'fec_info': fec_info,
        'decode_stats': decode_stats,
    }


def _render_decode_result(recovered: dict, output_name: str, file_id_hex: str | None,
                          encryption_mode: str, recipient_key_id: str | None,
                          signature_info: dict | None, fec_info: dict,
                          decode_stats: dict, qr_count: int):
    return render_template('decode_result.html', **_decode_result_context(
        recovered=recovered,
        output_name=output_name,
        file_id_hex=file_id_hex,
        encryption_mode=encryption_mode,
        recipient_key_id=recipient_key_id,
        signature_info=signature_info,
        fec_info=fec_info,
        decode_stats=decode_stats,
        qr_count=qr_count,
    ))


def _pending_template_name(pending: dict | None, fallback: str = 'decode.html') -> str:
    if pending and pending.get('origin_template') in ('decode.html', 'rescue.html'):
        return pending['origin_template']
    return fallback


def _complete_decode_from_blob(base_dir: str, temp_dir: str, output_dir: str, has_identity: bool, my_identity: dict | None,
                               encrypted_blob: bytes, fec_info: dict, decode_stats: dict, qr_count: int, file_id_hex: str | None, pending_template: str = 'decode.html'):
    crypto_info = inspect_crypto_blob(encrypted_blob)
    if crypto_info['mode'] == 'clear':
        packed, encryption_mode, recipient_key_id, signature_info = decrypt_file_payload_auto(encrypted_blob)
        recovered = unpack_file_payload(packed)

        output_name = f"restored_{timestamp_slug()}_{recovered['filename']}"
        output_path = os.path.join(output_dir, output_name)
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
            qr_count=qr_count,
        )

    pending_context = {
        'mode': crypto_info['mode'],
        'signed': crypto_info['signed'],
        'recipient_key_id': crypto_info.get('recipient_key_id'),
        'qr_count': qr_count,
        'file_id_hex': file_id_hex,
        'fec_info': fec_info,
        'decode_stats': decode_stats,
        'origin_template': pending_template,
    }
    token = _save_pending_state(temp_dir, encrypted_blob, pending_context)

    return render_template(
        pending_template,
        has_identity=has_identity,
        my_identity=my_identity,
        pending_decrypt=pending_context,
        pending_token=token,
    )


def _stage_decode_uploads(scan_pdf, scan_images, config: dict, task_id: str) -> tuple[str | None, list[str], str]:
    task_dir = os.path.join(config['TEMP_DIR'], f'decode_task_{task_id}')
    os.makedirs(task_dir, exist_ok=True)

    pdf_path = None
    image_paths: list[str] = []

    if scan_pdf and scan_pdf.filename:
        safe_name = secure_filename(scan_pdf.filename) or 'scan.pdf'
        pdf_path = os.path.join(task_dir, safe_name)
        scan_pdf.save(pdf_path)

    for idx, image in enumerate(scan_images, start=1):
        if not image or not image.filename:
            continue
        safe_name = secure_filename(image.filename) or f'image_{idx}.png'
        if os.path.exists(os.path.join(task_dir, safe_name)):
            stem, ext = os.path.splitext(safe_name)
            safe_name = f'{stem}_{idx}{ext}'
        image_path = os.path.join(task_dir, safe_name)
        image.save(image_path)
        image_paths.append(image_path)

    return pdf_path, image_paths, task_dir


def _cleanup_decode_uploads(task_dir: str | None) -> None:
    if task_dir and os.path.isdir(task_dir):
        shutil.rmtree(task_dir, ignore_errors=True)


def _run_decode_task(task_id: str, payload: dict) -> None:
    task_dir = payload.get('task_dir')
    try:
        base_dir = payload['base_dir']
        temp_dir = payload['temp_dir']
        output_dir = payload['output_dir']
        scan_pdf_path = payload.get('scan_pdf_path')
        scan_image_paths = payload.get('scan_image_paths') or []

        _update_decode_task(task_id, status='running', percent=5, stage='Preparing', message='Opening the uploaded files…')
        chunk_payloads, decode_stats = _collect_chunk_payloads_from_paths(scan_pdf_path, scan_image_paths, task_id=task_id)
        if not chunk_payloads:
            raise ValueError('No QR detected in the uploaded material.')

        _update_decode_task(task_id, status='running', percent=88, stage='Reconstruction', message='Reassembling the QRFS blob from the detected chunks…')
        encrypted_blob, fec_info = reconstruct_from_chunks(chunk_payloads)
        parsed_chunks = [parse_chunk(raw) for raw in chunk_payloads]
        file_id_hex = parsed_chunks[0].file_id.hex() if parsed_chunks else None
        qr_count = len(parsed_chunks)

        _update_decode_task(task_id, status='running', percent=95, stage='Inspection', message='Checking whether the reconstructed blob is cleartext or protected…')
        crypto_info = inspect_crypto_blob(encrypted_blob)
        my_identity = get_public_identity_no_password(base_dir)

        if crypto_info['mode'] == 'clear':
            packed, encryption_mode, recipient_key_id, signature_info = decrypt_file_payload_auto(encrypted_blob)
            recovered = unpack_file_payload(packed)
            output_name = f"restored_{timestamp_slug()}_{recovered['filename']}"
            output_path = os.path.join(output_dir, output_name)
            with open(output_path, 'wb') as f:
                f.write(recovered['file_bytes'])

            signature_info = _enrich_signature_info(base_dir, my_identity, signature_info)
            result = _decode_result_context(
                recovered=recovered,
                output_name=output_name,
                file_id_hex=file_id_hex,
                encryption_mode=encryption_mode,
                recipient_key_id=recipient_key_id,
                signature_info=signature_info,
                fec_info=fec_info,
                decode_stats=decode_stats,
                qr_count=qr_count,
            )
            _update_decode_task(
                task_id,
                status='done',
                percent=100,
                stage='Completed',
                message='File reconstructed successfully.',
                result=result,
            )
            return

        pending_context = {
            'mode': crypto_info['mode'],
            'signed': crypto_info['signed'],
            'recipient_key_id': crypto_info.get('recipient_key_id'),
            'qr_count': qr_count,
            'file_id_hex': file_id_hex,
            'fec_info': fec_info,
            'decode_stats': decode_stats,
            'origin_template': 'decode.html',
        }
        pending_token = _save_pending_state(temp_dir, encrypted_blob, pending_context)
        _update_decode_task(
            task_id,
            status='needs_unlock',
            percent=100,
            stage='Unlock required',
            message='Blob reconstructed. Open the unlock dialog to enter the password or private key.',
            pending_token=pending_token,
        )
    except Exception as exc:
        _update_decode_task(task_id, status='error', percent=100, stage='Error', message='Decoding failed.', error=str(exc))
    finally:
        _cleanup_decode_uploads(task_dir)


@decode_bp.route('/progress/<task_id>')
def decode_progress_view(task_id: str):
    task = _get_decode_task(task_id)
    if not task:
        flash('Decode task not found or expired.', 'error')
        return redirect(url_for('decode.decode_view'))
    return render_template('decode_progress.html', task_id=task_id)


@decode_bp.route('/progress/<task_id>/status')
def decode_progress_status(task_id: str):
    task = _get_decode_task(task_id)
    if not task:
        return jsonify({'error': 'task_not_found'}), 404
    redirect_url = None
    if task.get('status') == 'done':
        redirect_url = url_for('decode.decode_result_view', task_id=task_id)
    elif task.get('status') == 'needs_unlock':
        redirect_url = url_for('decode.decode_unlock_view', task_id=task_id)
    return jsonify({
        'task_id': task['task_id'],
        'status': task['status'],
        'percent': task.get('percent', 0),
        'stage': task.get('stage', ''),
        'message': task.get('message', ''),
        'error': task.get('error'),
        'redirect_url': redirect_url,
    })


@decode_bp.route('/result/<task_id>')
def decode_result_view(task_id: str):
    task = _get_decode_task(task_id)
    if not task:
        flash('Decode task not found or expired.', 'error')
        return redirect(url_for('decode.decode_view'))
    if task.get('status') == 'error':
        flash(f"Decoding failed: {task.get('error') or 'unknown error'}", 'error')
        return redirect(url_for('decode.decode_view'))
    if task.get('status') == 'needs_unlock':
        return redirect(url_for('decode.decode_unlock_view', task_id=task_id))
    if task.get('status') != 'done' or not task.get('result'):
        return redirect(url_for('decode.decode_progress_view', task_id=task_id))
    return render_template('decode_result.html', **task['result'])


@decode_bp.route('/unlock/<task_id>')
def decode_unlock_view(task_id: str):
    task = _get_decode_task(task_id)
    if not task:
        flash('Decode task not found or expired.', 'error')
        return redirect(url_for('decode.decode_view'))
    if task.get('status') == 'done':
        return redirect(url_for('decode.decode_result_view', task_id=task_id))
    if task.get('status') == 'error':
        flash(f"Decoding failed: {task.get('error') or 'unknown error'}", 'error')
        return redirect(url_for('decode.decode_view'))
    if task.get('status') != 'needs_unlock' or not task.get('pending_token'):
        return redirect(url_for('decode.decode_progress_view', task_id=task_id))

    base_dir = current_app.config['BASE_DIR']
    temp_dir = current_app.config['TEMP_DIR']
    has_identity = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)
    try:
        pending, _ = _load_pending_state(temp_dir, task['pending_token'])
    except Exception as exc:
        flash(str(exc), 'error')
        return redirect(url_for('decode.decode_view'))

    return render_template(
        'decode.html',
        has_identity=has_identity,
        my_identity=my_identity,
        pending_decrypt=pending,
        pending_token=task['pending_token'],
    )


@decode_bp.route('/', methods=['GET', 'POST'])
def decode_view():
    base_dir = current_app.config['BASE_DIR']
    temp_dir = current_app.config['TEMP_DIR']
    has_identity = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)

    if request.method == 'GET':
        return render_template('decode.html', has_identity=has_identity, my_identity=my_identity)

    action = request.form.get('action', 'scan').strip().lower()

    if action == 'cancel_pending':
        token = request.form.get('pending_token', '').strip()
        if token:
            _clear_pending_state(temp_dir, token)
        flash('Credential request cancelled.', 'info')
        return redirect(url_for('decode.decode_view'))

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
            return redirect(url_for('decode.decode_view'))

        if pending.get('mode') == 'pubkey' and use_identity and has_identity and master_password and not private_key:
            try:
                identity = unlock_identity(base_dir, master_password)
                private_key = identity['encryption_private_key_b64']
            except Exception as exc:
                return render_template(
                    'decode.html',
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
                _pending_template_name(pending),
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

    scan_pdf = request.files.get('scan_pdf')
    scan_images = request.files.getlist('scan_images')
    if not ((scan_pdf and scan_pdf.filename) or any(img and img.filename for img in scan_images)):
        flash('Select at least one PDF or image before starting decode.', 'error')
        return redirect(url_for('decode.decode_view'))

    task_id = _create_decode_task()
    try:
        scan_pdf_path, scan_image_paths, task_dir = _stage_decode_uploads(scan_pdf, scan_images, current_app.config, task_id)
    except Exception as exc:
        _cleanup_decode_uploads(os.path.join(current_app.config['TEMP_DIR'], f'decode_task_{task_id}'))
        _update_decode_task(task_id, status='error', percent=100, stage='Error', message='Unable to stage uploads.', error=str(exc))
        flash(f'Decode staging failed: {exc}', 'error')
        return redirect(url_for('decode.decode_view'))

    payload = {
        'base_dir': base_dir,
        'temp_dir': temp_dir,
        'output_dir': current_app.config['OUTPUT_DIR'],
        'task_dir': task_dir,
        'scan_pdf_path': scan_pdf_path,
        'scan_image_paths': scan_image_paths,
    }
    _update_decode_task(task_id, stage='Starting', message='Decode task created. Starting…')
    threading.Thread(target=_run_decode_task, args=(task_id, payload), daemon=True).start()
    return redirect(url_for('decode.decode_progress_view', task_id=task_id))


@decode_bp.route('/rescue', methods=['GET', 'POST'])
def rescue_view():
    base_dir = current_app.config['BASE_DIR']
    temp_dir = current_app.config['TEMP_DIR']
    has_identity = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)

    if request.method == 'GET':
        return render_template('rescue.html', has_identity=has_identity, my_identity=my_identity)

    action = request.form.get('action', 'rescue').strip().lower()

    if action == 'cancel_pending':
        token = request.form.get('pending_token', '').strip()
        if token:
            _clear_pending_state(temp_dir, token)
        flash('Credential request cancelled.', 'info')
        return redirect(url_for('decode.rescue_view'))

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
            return redirect(url_for('decode.rescue_view'))

        if pending.get('mode') == 'pubkey' and use_identity and has_identity and master_password and not private_key:
            try:
                identity = unlock_identity(base_dir, master_password)
                private_key = identity['encryption_private_key_b64']
            except Exception as exc:
                return render_template(
                    _pending_template_name(pending, 'rescue.html'),
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
                _pending_template_name(pending, 'rescue.html'),
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

    scan_pdf = request.files.get('scan_pdf')
    scan_images = request.files.getlist('scan_images')
    manual_chunks_text = request.form.get('manual_chunks', '')
    camera_chunk_data = request.form.get('chunk_data', '')

    chunk_payloads, decode_stats = _collect_chunk_payloads_from_files(scan_pdf, scan_images, current_app.config)

    if manual_chunks_text.strip():
        try:
            manual_payloads, manual_stats = _collect_manual_chunks(manual_chunks_text)
            chunk_payloads.extend(manual_payloads)
            decode_stats = _merge_decode_stats(decode_stats, manual_stats)
        except Exception as exc:
            flash(f'Manual rescue: {exc}', 'error')
            return redirect(url_for('decode.rescue_view'))

    if camera_chunk_data.strip():
        try:
            camera_payloads, camera_stats = _collect_camera_chunks(camera_chunk_data)
            chunk_payloads.extend(camera_payloads)
            decode_stats = _merge_decode_stats(decode_stats, camera_stats)
        except Exception as exc:
            flash(f'Camera rescue: {exc}', 'error')
            return redirect(url_for('decode.rescue_view'))

    if not chunk_payloads:
        flash('No QR detected or pasted.', 'error')
        return redirect(url_for('decode.rescue_view'))

    try:
        encrypted_blob, fec_info = reconstruct_from_chunks(chunk_payloads)
    except Exception as exc:
        flash(f'Decoding failed: {exc}', 'error')
        return redirect(url_for('decode.rescue_view'))

    parsed_chunks = [parse_chunk(raw) for raw in chunk_payloads]
    file_id_hex = parsed_chunks[0].file_id.hex() if parsed_chunks else None

    try:
        return _complete_decode_from_blob(
            base_dir=base_dir,
            temp_dir=temp_dir,
            output_dir=current_app.config['OUTPUT_DIR'],
            has_identity=has_identity,
            my_identity=my_identity,
            encrypted_blob=encrypted_blob,
            fec_info=fec_info,
            decode_stats=decode_stats,
            qr_count=len(parsed_chunks),
            file_id_hex=file_id_hex,
            pending_template='rescue.html',
        )
    except Exception as exc:
        flash(f'Decoding failed: {exc}', 'error')
        return redirect(url_for('decode.rescue_view'))



def _collect_camera_chunks(raw_text: str) -> tuple[list[bytes], dict]:
    stats = _build_empty_decode_stats()
    payloads: list[bytes] = []
    seen: set[bytes] = set()
    entries = [entry.strip() for entry in raw_text.splitlines() if entry.strip()]
    for idx, entry in enumerate(entries, start=1):
        try:
            decoded = b45decode(entry)
        except Exception as exc:
            raise ValueError(f'Camera item {idx}: invalid Base45 ({exc}).') from exc
        if not decoded.startswith((b'QRC1', b'QRC2', b'QRC3')):
            raise ValueError(f'Camera item {idx}: does not look like a QRFS chunk.')
        if decoded in seen:
            stats['duplicates_discarded'] += 1
            continue
        seen.add(decoded)
        payloads.append(decoded)
        stats['manual_qr_added'] += 1
        stats['qr_total_seen'] += 1
        stats['qr_unique'] += 1
    return payloads, stats


@decode_bp.route('/preview/<path:filename>')
def preview_restored(filename: str):
    path = os.path.join(current_app.config['OUTPUT_DIR'], filename)
    if not os.path.isfile(path):
        flash('Preview unavailable: file not found.', 'error')
        return redirect(url_for('decode.decode_view'))
    guessed, _ = mimetypes.guess_type(path)
    return send_file(path, as_attachment=False, mimetype=guessed or 'application/octet-stream')


@decode_bp.route('/download/<path:filename>')
def download_restored(filename: str):
    path = os.path.join(current_app.config['OUTPUT_DIR'], filename)
    if not os.path.isfile(path):
        flash('File not found.', 'error')
        return redirect(url_for('decode.decode_view'))
    return send_file(path, as_attachment=True)
