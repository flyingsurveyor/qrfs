import io
import json

from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, make_response, send_file

from ..core.keystore import (
    identity_exists,
    generate_identity,
    unlock_identity,
    get_public_identity_no_password,
    delete_identity,
    export_identity_card,
    export_identity_backup,
    export_identity_recovery_sheet,
    import_identity_backup,
    import_identity_from_private_keys,
    import_identity_recovery_sheet,
)
from ..core.key_utils import qr_png_data_uri, build_public_key_qr_payload, build_identity_card_payload

keys_bp = Blueprint('keys', __name__, url_prefix='/keys')


def _json_download(payload: dict | bytes, filename: str):
    if isinstance(payload, dict):
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
    else:
        data = payload
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype='application/json')


@keys_bp.route('/', methods=['GET', 'POST'])
def keys_view():
    base_dir = current_app.config['BASE_DIR']
    has_identity = identity_exists(base_dir)
    unlocked = None
    qr_data = {}
    public_info = None
    public_info_warning = None

    try:
        public_info = get_public_identity_no_password(base_dir)
    except Exception as e:
        public_info = None
        public_info_warning = f'Unreadable public identity data: {e}'

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        master_pw = request.form.get('master_password', '').strip()
        master_pw_confirm = (request.form.get('master_password_confirm') or '').strip()
        display_name = (request.form.get('display_name') or '').strip()

        if action == 'generate':
            if master_pw != master_pw_confirm:
                flash('The master passwords do not match.', 'error')
                return redirect(url_for('keys.keys_view'))
            try:
                public_info = generate_identity(base_dir, master_pw, display_name=display_name)
                has_identity = True
                flash('Identity generated and saved!', 'success')
            except Exception as e:
                flash(f'Error: {e}', 'error')
            return redirect(url_for('keys.keys_view'))

        if action == 'unlock':
            try:
                unlocked = unlock_identity(base_dir, master_pw)
                flash('Identity unlocked.', 'success')
            except Exception as e:
                flash(f'Error: {e}', 'error')
                return redirect(url_for('keys.keys_view'))

        if action == 'delete':
            delete_identity(base_dir)
            flash('Identity deleted.', 'success')
            return redirect(url_for('keys.keys_view'))

        if action == 'download_card':
            try:
                payload = export_identity_card(base_dir)
                return _json_download(payload, 'qrfs_identity_card.json')
            except Exception as e:
                flash(f'Identity card export error: {e}', 'error')
                return redirect(url_for('keys.keys_view'))

        if action == 'export_backup':
            backup_password = (request.form.get('backup_password') or '').strip()
            backup_password_confirm = (request.form.get('backup_password_confirm') or '').strip()
            if backup_password and backup_password != backup_password_confirm:
                flash('The backup passwords do not match.', 'error')
                return redirect(url_for('keys.keys_view'))
            try:
                payload = export_identity_backup(base_dir, master_pw, backup_password=backup_password or None)
                return _json_download(payload, 'qrfs_identity_backup.json')
            except Exception as e:
                flash(f'Backup export error: {e}', 'error')
                return redirect(url_for('keys.keys_view'))

        if action == 'download_recovery_sheet':
            try:
                payload = export_identity_recovery_sheet(base_dir, master_pw)
                return _json_download(payload, 'qrfs_identity_recovery_sheet.json')
            except Exception as e:
                flash(f'Recovery sheet export error: {e}', 'error')
                return redirect(url_for('keys.keys_view'))

        if action == 'import_backup':
            backup_password = (request.form.get('backup_import_password') or '').strip()
            new_master_password = (request.form.get('new_master_password') or '').strip()
            new_master_password_confirm = (request.form.get('new_master_password_confirm') or '').strip()
            overwrite = request.form.get('overwrite_identity') == 'on'
            upload = request.files.get('backup_file')
            backup_text = (request.form.get('backup_payload') or '').strip()
            backup_blob: bytes | str = backup_text
            if upload and upload.filename:
                backup_blob = upload.read()
            if not backup_blob:
                flash('Select or paste an identity backup to import.', 'error')
                return redirect(url_for('keys.keys_view'))
            if new_master_password and new_master_password != new_master_password_confirm:
                flash('The new master passwords do not match.', 'error')
                return redirect(url_for('keys.keys_view'))
            try:
                public_info = import_identity_backup(
                    base_dir,
                    backup_blob,
                    backup_password=backup_password,
                    new_master_password=new_master_password or None,
                    overwrite=overwrite,
                )
                has_identity = True
                flash('Identity backup imported successfully.', 'success')
            except Exception as e:
                flash(f'Backup import error: {e}', 'error')
            return redirect(url_for('keys.keys_view'))

        if action == 'import_recovery':
            overwrite = request.form.get('overwrite_identity') == 'on'
            recovery_upload = request.files.get('recovery_file')
            recovery_text = (request.form.get('recovery_payload') or '').strip()
            recovery_blob: bytes | str = recovery_text
            if recovery_upload and recovery_upload.filename:
                recovery_blob = recovery_upload.read()
            master_password_new = (request.form.get('recovery_master_password') or '').strip()
            master_password_new_confirm = (request.form.get('recovery_master_password_confirm') or '').strip()
            display_name_override = (request.form.get('recovery_display_name') or '').strip()
            enc_private = (request.form.get('recovery_encryption_private_key') or '').strip()
            sign_private = (request.form.get('recovery_signing_private_key') or '').strip()
            if master_password_new != master_password_new_confirm:
                flash('The new master passwords do not match.', 'error')
                return redirect(url_for('keys.keys_view'))
            try:
                if recovery_blob:
                    public_info = import_identity_recovery_sheet(
                        base_dir,
                        recovery_blob,
                        master_password=master_password_new,
                        overwrite=overwrite,
                    )
                else:
                    if not enc_private or not sign_private:
                        flash('Paste both private keys or upload a recovery sheet.', 'error')
                        return redirect(url_for('keys.keys_view'))
                    public_info = import_identity_from_private_keys(
                        base_dir,
                        encryption_private_key_b64=enc_private,
                        signing_private_key_b64=sign_private,
                        master_password=master_password_new,
                        display_name=display_name_override,
                        overwrite=overwrite,
                    )
                has_identity = True
                flash('Identity imported from private material.', 'success')
            except Exception as e:
                flash(f'Private-key import error: {e}', 'error')
            return redirect(url_for('keys.keys_view'))

    if public_info:
        try:
            enc_qr_payload = build_public_key_qr_payload(
                kind='x25519',
                public_key_b64=public_info['encryption_public_key_b64'],
                key_id=public_info['encryption_key_id'],
                fingerprint=public_info['encryption_fingerprint'],
            )
            sign_qr_payload = build_public_key_qr_payload(
                kind='ed25519',
                public_key_b64=public_info['signing_public_key_b64'],
                key_id=public_info['signing_key_id'],
                fingerprint=public_info['signing_fingerprint'],
            )
            identity_card_payload = build_identity_card_payload(
                display_name=public_info.get('display_name') or '',
                encryption_public_key_b64=public_info['encryption_public_key_b64'],
                signing_public_key_b64=public_info['signing_public_key_b64'],
                created_at=public_info.get('created_at'),
                notes=public_info.get('notes') or '',
            )
            qr_data = {
                'enc_qr_uri': qr_png_data_uri(enc_qr_payload),
                'sign_qr_uri': qr_png_data_uri(sign_qr_payload),
                'identity_qr_uri': qr_png_data_uri(identity_card_payload),
                'enc_qr_payload': enc_qr_payload,
                'sign_qr_payload': sign_qr_payload,
                'identity_card_payload': identity_card_payload,
                'identity_card_pretty': json.dumps(public_info, ensure_ascii=False, indent=2),
            }
        except Exception as e:
            qr_data = {}
            public_info_warning = f'Unable to generate the public QR materials: {e}'

    response = make_response(render_template(
        'keys.html',
        has_identity=has_identity,
        public_info=public_info,
        public_info_warning=public_info_warning,
        unlocked=unlocked,
        qr_data=qr_data,
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
