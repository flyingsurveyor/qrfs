from flask import Blueprint, current_app, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from ..core.crypto_utils import encrypt_file_payload_clear, encrypt_file_payload_password, encrypt_file_payload_pubkey
from ..core.chunker import make_chunks
from ..core.pdfgen import PER_PAGE, build_qr_pdf, build_png_zip
from ..core.packaging import pack_file_payload
from ..core.utils import human_bytes, timestamp_slug, percent_str
from ..core.estimate import estimate_encode_sizes
from ..core.manifest import build_manifest_dict, save_manifest_json
from ..core.key_utils import normalize_public_key_input
from ..core.qrdecode import decode_qr_bytes_from_images, decode_qr_bytes_from_pdf
from ..core.address_book import load_contacts, get_contact
from ..core.keystore import identity_exists, get_public_identity_no_password, unlock_identity
import os
import threading
import time
import uuid

encode_bp = Blueprint('encode', __name__, url_prefix='/encode')

# Chunk sizes per preset per ECC level.
# Same physical QR version & module size — only internal capacity changes.
PRESETS = {
    'robusto':  {'M': 450, 'L': 640},
    'standard': {'M': 650, 'L': 900},
    'denso':    {'M': 800, 'L': 1100},
}

CHUNK_SIZE_OPTIONS = {
    'preset': None,
    '1200': 1200,
}

ENCODE_TASKS = {}
ENCODE_TASKS_LOCK = threading.Lock()
TASK_TTL_SECONDS = 60 * 60 * 12


def _cleanup_old_tasks() -> None:
    cutoff = time.time() - TASK_TTL_SECONDS
    with ENCODE_TASKS_LOCK:
        stale = [task_id for task_id, task in ENCODE_TASKS.items() if task.get('updated_at', 0) < cutoff]
        for task_id in stale:
            ENCODE_TASKS.pop(task_id, None)


def _create_task() -> str:
    _cleanup_old_tasks()
    task_id = uuid.uuid4().hex
    with ENCODE_TASKS_LOCK:
        ENCODE_TASKS[task_id] = {
            'task_id': task_id,
            'status': 'queued',
            'percent': 0,
            'stage': 'Queued',
            'message': 'Preparing request…',
            'created_at': time.time(),
            'updated_at': time.time(),
            'result': None,
            'error': None,
        }
    return task_id


def _update_task(task_id: str, **fields) -> None:
    with ENCODE_TASKS_LOCK:
        task = ENCODE_TASKS.get(task_id)
        if not task:
            return
        task.update(fields)
        task['updated_at'] = time.time()


def _get_task(task_id: str):
    with ENCODE_TASKS_LOCK:
        task = ENCODE_TASKS.get(task_id)
        return dict(task) if task else None


def _pdf_progress_updater(task_id: str, start_percent: int = 28, end_percent: int = 92):
    def _callback(done: int, total: int):
        pct = start_percent if total <= 0 else start_percent + int((done / total) * (end_percent - start_percent))
        _update_task(
            task_id,
            status='running',
            percent=min(max(pct, start_percent), end_percent),
            stage='PDF creation',
            message=f'Generating page {done}/{total} of the PDF…',
        )
    return _callback


def _png_progress_updater(task_id: str, start_percent: int = 92, end_percent: int = 98):
    def _callback(done: int, total: int):
        pct = start_percent if total <= 0 else start_percent + int((done / total) * (end_percent - start_percent))
        _update_task(
            task_id,
            status='running',
            percent=min(max(pct, start_percent), end_percent),
            stage='Optional PNG',
            message=f'Generating PNG page images {done}/{total}…',
        )
    return _callback




def _redirect_back(return_to: str | None):
    route_key = (return_to or '').strip().lower()
    if route_key == 'voice':
        target = 'encode.voice_view'
    elif route_key == 'photo':
        target = 'encode.photo_view'
    else:
        target = 'encode.encode_view'
    return redirect(url_for(target))

def _build_display_label(safe_name: str, encryption_mode: str, return_to: str | None) -> str:
    if encryption_mode != 'clear':
        return '*ENCRYPTED*'
    route_key = (return_to or '').strip().lower()
    if route_key == 'voice':
        return 'AUDIO'
    if route_key == 'photo':
        return 'IMAGE'
    ext = os.path.splitext((safe_name or '').strip())[1].lstrip('.').strip()
    return ext.upper() if ext else 'BINARY'

def _run_encode_task(task_id: str, payload: dict) -> None:
    try:
        safe_name = payload['safe_name']
        file_bytes = payload['file_bytes']
        mime_type = payload['mime_type']
        compress = payload['compress']
        signing_private_key = payload['signing_private_key']
        encryption_mode = payload['encryption_mode']
        password = payload['password']
        public_key = payload['public_key']
        chunk_size = payload['chunk_size']
        fec_group_size = payload['fec_group_size']
        fec_type = payload['fec_type']
        fec_parity_count = payload['fec_parity_count']
        preset = payload['preset']
        qr_ecc = payload['qr_ecc']
        generate_png_zip = payload['generate_png_zip']
        output_dir = payload['output_dir']
        display_label = payload['display_label']

        _update_task(task_id, status='running', percent=5, stage='Preparing file', message='Packaging content…')
        packed = pack_file_payload(filename=safe_name, mime_type=mime_type,
                                   file_bytes=file_bytes, compress=compress)

        signed = bool(signing_private_key)
        _update_task(task_id, percent=12, stage='Content protection', message='Encrypting or signing the payload…')
        if encryption_mode == 'clear':
            encrypted = encrypt_file_payload_clear(packed,
                                                   sender_signing_private_key_b64=signing_private_key or None)
        elif encryption_mode == 'pubkey':
            encrypted = encrypt_file_payload_pubkey(packed, public_key,
                                                    sender_signing_private_key_b64=signing_private_key or None)
        else:
            encrypted = encrypt_file_payload_password(packed, password,
                                                      sender_signing_private_key_b64=signing_private_key or None)

        _update_task(task_id, percent=20, stage='Chunking', message='Splitting the blob into QR codes…')
        chunks = make_chunks(encrypted, chunk_size=chunk_size,
                             fec_group_size=fec_group_size, fec_parity_count=fec_parity_count,
                             fec_type=fec_type)
        estimate = estimate_encode_sizes(len(file_bytes), len(packed), len(encrypted),
                                         chunk_size, fec_group_size=fec_group_size,
                                         fec_parity_count=fec_parity_count)

        stem = f"qrfs_{timestamp_slug()}"
        output_pdf = os.path.join(output_dir, f'{stem}.pdf')
        output_png_zip = os.path.join(output_dir, f'{stem}_png.zip')
        output_manifest = os.path.join(output_dir, f'{stem}_manifest.json')

        total_pages = max(1, (len(chunks) + PER_PAGE - 1) // PER_PAGE)
        _update_task(task_id, percent=28, stage='PDF creation', message=f'Generating the PDF ({total_pages} pages)…')
        build_qr_pdf(
            chunks,
            output_pdf,
            original_filename=safe_name,
            ecc_level=qr_ecc,
            display_label=display_label,
            progress_callback=_pdf_progress_updater(task_id),
        )

        png_zip_name = None
        if generate_png_zip:
            _update_task(task_id, percent=92, stage='Optional PNG', message='Also generating the PNG ZIP…')
            build_png_zip(
                chunks,
                output_png_zip,
                original_filename=safe_name,
                ecc_level=qr_ecc,
                display_label=display_label,
                progress_callback=_png_progress_updater(task_id),
            )
            png_zip_name = os.path.basename(output_png_zip)

        _update_task(task_id, percent=99, stage='Manifest', message='Saving the technical manifest…')
        manifest = build_manifest_dict(
            original_filename=safe_name, mime_type=mime_type,
            original_bytes=file_bytes, packed_bytes=packed, encrypted_bytes=encrypted,
            chunks=chunks, compress_requested=compress, preset=preset,
            chunk_size=chunk_size, encryption_mode=encryption_mode, signed=signed,
            fec_group_size=fec_group_size, fec_type=fec_type, fec_parity_count=fec_parity_count,
        )
        manifest['qr_ecc_level'] = qr_ecc
        save_manifest_json(manifest, output_manifest)

        result = {
            'filename': safe_name,
            'original_size': human_bytes(len(file_bytes)),
            'packed_size': human_bytes(len(packed)),
            'encrypted_size': human_bytes(len(encrypted)),
            'qr_count': len(chunks),
            'page_count': total_pages,
            'mime_type': mime_type,
            'chunk_size': chunk_size,
            'preset': preset,
            'qr_ecc': qr_ecc,
            'encryption_mode': encryption_mode,
            'signed': signed,
            'fec_group_size': fec_group_size,
            'fec_type': fec_type,
            'fec_parity_count': fec_parity_count,
            'fec_parity_chunks': estimate.fec_parity_chunks,
            'compression_gain': human_bytes(len(file_bytes) - len(packed)) if len(packed) < len(file_bytes) else 'none',
            'chunk_header_total': human_bytes(estimate.chunk_header_total),
            'overhead_total': human_bytes(estimate.overhead_total),
            'overhead_ratio': percent_str(estimate.overhead_ratio),
            'pdf_name': os.path.basename(output_pdf),
            'png_zip_name': png_zip_name,
            'manifest_name': os.path.basename(output_manifest),
            'generate_png_zip': generate_png_zip,
        }
        _update_task(task_id, status='done', percent=100, stage='Completed', message='Output ready.', result=result)
    except Exception as e:
        _update_task(task_id, status='error', percent=100, stage='Error', message='Encoding failed.', error=str(e))




@encode_bp.route('/voice', methods=['GET'])
def voice_view():
    base_dir = current_app.config['BASE_DIR']
    contacts = load_contacts(base_dir)
    has_id = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)
    return render_template('voice.html', contacts=contacts,
                           has_identity=has_id, my_identity=my_identity)


@encode_bp.route('/photo', methods=['GET'])
def photo_view():
    base_dir = current_app.config['BASE_DIR']
    contacts = load_contacts(base_dir)
    has_id = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)
    return render_template('photo.html', contacts=contacts,
                           has_identity=has_id, my_identity=my_identity)


@encode_bp.route('/', methods=['GET', 'POST'])
def encode_view():
    base_dir = current_app.config['BASE_DIR']
    contacts = load_contacts(base_dir)
    has_id = identity_exists(base_dir)
    my_identity = get_public_identity_no_password(base_dir)

    if request.method == 'GET':
        return render_template('encode.html', contacts=contacts,
                               has_identity=has_id, my_identity=my_identity)

    return_to = request.form.get('return_to', '').strip().lower()

    uploaded = request.files.get('file')
    encryption_mode = request.form.get('encryption_mode', 'password').strip()
    password = request.form.get('password', '').strip()
    password_confirm = request.form.get('password_confirm', '').strip()
    public_key = request.form.get('public_key', '').strip()
    contact_id = request.form.get('contact_id', '').strip()
    public_key_qr = request.files.get('public_key_qr')
    compress = request.form.get('compress') == 'on'
    fec_group_size = int(request.form.get('fec_group_size', '0') or '0')
    fec_type = request.form.get('fec_type', 'xor').strip().lower()
    fec_parity_count = int(request.form.get('fec_parity_count', '1') or '1')
    preset = request.form.get('preset', 'standard').strip().lower()
    chunk_size_mode = request.form.get('chunk_size_mode', 'preset').strip().lower()
    legacy_chunk_size_raw = request.form.get('chunk_size', '').strip()
    qr_ecc = request.form.get('qr_ecc', 'M').strip().upper()
    generate_png_zip = request.form.get('generate_png_zip') == 'on'

    if qr_ecc not in ('L', 'M', 'Q', 'H'):
        qr_ecc = 'M'

    # ── Signing key ──
    signing_private_key = request.form.get('signing_private_key', '').strip()
    sign_with_identity = request.form.get('sign_with_identity') == 'on'
    master_password = request.form.get('master_password', '').strip()

    if sign_with_identity and has_id:
        if not master_password and not signing_private_key:
            flash('Enter the master password to sign with your identity.', 'error')
            return _redirect_back(return_to)
        if master_password:
            try:
                identity = unlock_identity(base_dir, master_password)
                signing_private_key = identity['signing_private_key_b64']
            except Exception as e:
                flash(f'Identity unlock failed: {e}', 'error')
                return _redirect_back(return_to)

    if not uploaded or not uploaded.filename:
        flash('Select a file to encode.', 'error')
        return _redirect_back(return_to)

    if encryption_mode == 'password':
        if len(password) < 14:
            flash('Password: at least 14 characters.', 'error')
            return _redirect_back(return_to)
        if password != password_confirm:
            flash('The two passwords do not match.', 'error')
            return _redirect_back(return_to)

    # ── Resolve recipient public key ──
    if encryption_mode not in ('clear', 'password', 'pubkey'):
        encryption_mode = 'password'

    if fec_group_size not in (0, 3, 5, 8):
        flash('Unsupported FEC group size for this form.', 'error')
        return _redirect_back(return_to)
    if fec_type not in ('xor', 'rs'):
        flash('Unsupported FEC type.', 'error')
        return _redirect_back(return_to)
    if fec_group_size == 0:
        fec_parity_count = 0
    if fec_type == 'xor' and fec_group_size and fec_parity_count != 1:
        flash('XOR FEC supports exactly 1 parity QR per group.', 'error')
        return _redirect_back(return_to)
    if fec_type == 'rs' and fec_group_size and (fec_parity_count < 1 or fec_parity_count >= fec_group_size):
        flash('For Reed-Solomon, parity QR per group must be at least 1 and smaller than the number of data QR in the group.', 'error')
        return _redirect_back(return_to)

    if encryption_mode == 'pubkey':
        if contact_id == '__self__' and has_id:
            if not master_password:
                flash('Enter the master password to encrypt to yourself.', 'error')
                return _redirect_back(return_to)
            try:
                identity = unlock_identity(base_dir, master_password)
                public_key = identity['encryption_public_key_b64']
            except Exception as e:
                flash(f'Identity unlock: {e}', 'error')
                return _redirect_back(return_to)
        elif contact_id and contact_id != '__self__' and not public_key:
            contact = get_contact(base_dir, contact_id)
            if contact:
                public_key = (contact.get('encryption_public_key_b64') or contact.get('public_key_b64') or '').strip()

        if not public_key and public_key_qr and public_key_qr.filename:
            temp_path = os.path.join(current_app.config['TEMP_DIR'],
                                     f"pubkey_{timestamp_slug()}_{secure_filename(public_key_qr.filename)}")
            public_key_qr.save(temp_path)
            try:
                if temp_path.lower().endswith('.pdf'):
                    decoded_items = decode_qr_bytes_from_pdf(temp_path)
                else:
                    decoded_items = decode_qr_bytes_from_images([temp_path])
                if not decoded_items:
                    flash('No QR found in the key file.', 'error')
                    return _redirect_back(return_to)
                public_key = decoded_items[0].decode('utf-8', errors='strict').strip()
            except Exception as e:
                flash(f'Key QR read: {e}', 'error')
                return _redirect_back(return_to)
            finally:
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        if public_key:
            try:
                public_key = normalize_public_key_input(public_key, expected_kind='x25519')
            except Exception as e:
                flash(f'Invalid public key: {e}', 'error')
                return _redirect_back(return_to)

        if not public_key:
            flash('Select a recipient or paste a public key.', 'error')
            return _redirect_back(return_to)

    # ── Chunk size: dropdown override or preset+ecc ──
    preset_data = PRESETS.get(preset, PRESETS['standard'])
    chunk_size = preset_data.get(qr_ecc, preset_data.get('M', 650))

    if chunk_size_mode in CHUNK_SIZE_OPTIONS and CHUNK_SIZE_OPTIONS[chunk_size_mode] is not None:
        chunk_size = CHUNK_SIZE_OPTIONS[chunk_size_mode]
    elif legacy_chunk_size_raw:
        # Compatibility with old forms / manual requests
        chunk_size = int(legacy_chunk_size_raw)

    safe_name = secure_filename(uploaded.filename) or 'input.bin'
    file_bytes = uploaded.read()
    mime_type = uploaded.mimetype or 'application/octet-stream'
    display_label = _build_display_label(safe_name, encryption_mode, return_to)

    task_id = _create_task()
    payload = {
        'safe_name': safe_name,
        'file_bytes': file_bytes,
        'mime_type': mime_type,
        'compress': compress,
        'signing_private_key': signing_private_key,
        'encryption_mode': encryption_mode,
        'password': password,
        'public_key': public_key,
        'chunk_size': chunk_size,
        'fec_group_size': fec_group_size,
        'fec_type': fec_type,
        'fec_parity_count': fec_parity_count,
        'preset': preset,
        'qr_ecc': qr_ecc,
        'generate_png_zip': generate_png_zip,
        'output_dir': current_app.config['OUTPUT_DIR'],
        'display_label': display_label,
    }
    _update_task(task_id, stage='Starting', message='Encoding task created. Starting…')
    threading.Thread(target=_run_encode_task, args=(task_id, payload), daemon=True).start()
    return redirect(url_for('encode.encode_progress_view', task_id=task_id))


@encode_bp.route('/progress/<task_id>')
def encode_progress_view(task_id: str):
    task = _get_task(task_id)
    if not task:
        flash('Encoding task not found or expired.', 'error')
        return redirect(url_for('encode.encode_view'))
    return render_template('encode_progress.html', task_id=task_id)


@encode_bp.route('/progress/<task_id>/status')
def encode_progress_status(task_id: str):
    task = _get_task(task_id)
    if not task:
        return jsonify({'error': 'task_not_found'}), 404
    return jsonify({
        'task_id': task['task_id'],
        'status': task['status'],
        'percent': task.get('percent', 0),
        'stage': task.get('stage', ''),
        'message': task.get('message', ''),
        'error': task.get('error'),
        'result_url': url_for('encode.encode_result_view', task_id=task_id) if task.get('status') == 'done' else None,
    })


@encode_bp.route('/result/<task_id>')
def encode_result_view(task_id: str):
    task = _get_task(task_id)
    if not task:
        flash('Encoding task not found or expired.', 'error')
        return redirect(url_for('encode.encode_view'))
    if task.get('status') == 'error':
        flash(f"Encoding failed: {task.get('error') or 'unknown error'}", 'error')
        return redirect(url_for('encode.encode_view'))
    if task.get('status') != 'done' or not task.get('result'):
        return redirect(url_for('encode.encode_progress_view', task_id=task_id))
    return render_template('encode_result.html', **task['result'])


@encode_bp.route('/download/<path:filename>')
def download_output(filename: str):
    path = os.path.join(current_app.config['OUTPUT_DIR'], filename)
    if not os.path.isfile(path):
        flash('File not found.', 'error')
        return redirect(url_for('encode.encode_view'))
    return send_file(path, as_attachment=True)
