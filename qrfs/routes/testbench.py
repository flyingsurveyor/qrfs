from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
import json
import os

from ..core.testbench import run_testbench
from ..core.utils import timestamp_slug


testbench_bp = Blueprint('testbench', __name__, url_prefix='/testbench')


@testbench_bp.route('/', methods=['GET', 'POST'])
def testbench_view():
    if request.method == 'GET':
        return render_template('testbench.html')

    try:
        file_size = int(request.form.get('file_size', '65536') or '65536')
        trials = int(request.form.get('trials', '3') or '3')
        chunk_size = int(request.form.get('chunk_size', '900') or '900')
        fec_group_size = int(request.form.get('fec_group_size', '0') or '0')
        fec_type = (request.form.get('fec_type', 'xor') or 'xor').strip()
        fec_parity_count = int(request.form.get('fec_parity_count', '1') or '1')
        encryption_mode = (request.form.get('encryption_mode', 'password') or 'password').strip()
        password = (request.form.get('password', 'testbench-password') or 'testbench-password').strip()
        remove_mode = (request.form.get('remove_mode', 'single_any') or 'single_any').strip()
        pattern = (request.form.get('pattern', 'mixed') or 'mixed').strip()
        compress = request.form.get('compress') == 'on'
        sign = request.form.get('sign') == 'on'
        if fec_group_size == 0:
            fec_parity_count = 0
        if fec_type == 'xor' and fec_group_size and fec_parity_count != 1:
            raise ValueError('XOR FEC supports exactly 1 parity chunk per group.')
        if fec_type == 'rs' and fec_group_size and fec_parity_count >= fec_group_size:
            raise ValueError('For Reed-Solomon, parity chunks per group must be smaller than the number of data chunks.')
    except Exception as exc:
        flash(f'Invalid testbench parameters: {exc}', 'error')
        return redirect(url_for('testbench.testbench_view'))

    try:
        report = run_testbench(
            file_size=file_size,
            trials=trials,
            encryption_mode=encryption_mode,
            password=password,
            chunk_size=chunk_size,
            fec_group_size=fec_group_size,
            compress=compress,
            sign=sign,
            remove_mode=remove_mode,
            pattern=pattern,
            fec_type=fec_type,
            fec_parity_count=fec_parity_count,
        )
    except Exception as exc:
        flash(f'Testbench failed: {exc}', 'error')
        return redirect(url_for('testbench.testbench_view'))

    stem = f"qrfs_testbench_{timestamp_slug()}"
    out_path = os.path.join(current_app.config['OUTPUT_DIR'], f'{stem}.json')
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    return render_template('testbench_result.html', report=report, report_name=os.path.basename(out_path))


@testbench_bp.route('/download/<path:filename>')
def download_report(filename: str):
    path = os.path.join(current_app.config['OUTPUT_DIR'], filename)
    if not os.path.isfile(path):
        flash('Testbench report not found.', 'error')
        return redirect(url_for('testbench.testbench_view'))
    return send_file(path, as_attachment=True)
