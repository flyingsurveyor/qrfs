from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename
import os

from ..core.address_book import add_contact, delete_contact, load_contacts
from ..core.qrdecode import decode_qr_bytes_from_images, decode_qr_bytes_from_pdf


contacts_bp = Blueprint('contacts', __name__, url_prefix='/contacts')


@contacts_bp.route('/', methods=['GET', 'POST'])
def contacts_view():
    base_dir = current_app.config['BASE_DIR']

    if request.method == 'POST':
        action = (request.form.get('action') or 'add').strip()
        if action == 'delete':
            contact_id = (request.form.get('contact_id') or '').strip()
            if delete_contact(base_dir, contact_id):
                flash('Contact removed from the address book.', 'success')
            else:
                flash('Contact not found.', 'error')
            return redirect(url_for('contacts.contacts_view'))

        name = (request.form.get('name') or '').strip()
        public_key_input = (request.form.get('public_key') or '').strip()
        note = (request.form.get('note') or '').strip()
        key_qr = request.files.get('public_key_qr')

        if not public_key_input and key_qr and key_qr.filename:
            temp_key_qr_path = os.path.join(current_app.config['TEMP_DIR'], f"contact_import_{secure_filename(key_qr.filename)}")
            key_qr.save(temp_key_qr_path)
            try:
                lower = temp_key_qr_path.lower()
                if lower.endswith('.pdf'):
                    decoded_items = decode_qr_bytes_from_pdf(temp_key_qr_path)
                    if not decoded_items:
                        flash('No QR found in the uploaded file.', 'error')
                        return redirect(url_for('contacts.contacts_view'))
                    public_key_input = decoded_items[0].decode('utf-8', errors='strict').strip()
                elif lower.endswith(('.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif')):
                    decoded_items = decode_qr_bytes_from_images([temp_key_qr_path])
                    if not decoded_items:
                        flash('No QR found in the uploaded file.', 'error')
                        return redirect(url_for('contacts.contacts_view'))
                    public_key_input = decoded_items[0].decode('utf-8', errors='strict').strip()
                else:
                    with open(temp_key_qr_path, 'r', encoding='utf-8') as f:
                        public_key_input = f.read().strip()
            except Exception as exc:
                flash(f'Unable to read the contact material: {exc}', 'error')
                return redirect(url_for('contacts.contacts_view'))
            finally:
                try:
                    os.remove(temp_key_qr_path)
                except OSError:
                    pass

        try:
            contact = add_contact(base_dir, name=name, public_key_input=public_key_input, note=note)
            signing_part = f", signing {contact['signing_key_id']}" if contact.get('signing_key_id') else ''
            flash(f"Contact saved: {contact['name']} (enc {contact['encryption_key_id']}{signing_part}).", 'success')
        except Exception as exc:
            flash(f'Unable to save the contact: {exc}', 'error')
        return redirect(url_for('contacts.contacts_view'))

    contacts = load_contacts(base_dir)
    return render_template('contacts.html', contacts=contacts)
