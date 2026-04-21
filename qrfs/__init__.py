from flask import Flask, render_template
from .routes import contacts_bp, decode_bp, encode_bp, keys_bp, scan_bp, testbench_bp
import os
import secrets

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(PACKAGE_DIR)


def _get_secret_key() -> str:
    env_key = os.environ.get('QRFS_SECRET_KEY')
    if env_key:
        return env_key

    data_dir = os.path.join(BASE_DIR, 'data')
    os.makedirs(data_dir, exist_ok=True)
    key_path = os.path.join(data_dir, '.flask_secret_key')

    try:
        if os.path.exists(key_path):
            with open(key_path, 'r', encoding='utf-8') as fh:
                key = fh.read().strip()
                if key:
                    return key

        key = secrets.token_hex(32)
        with open(key_path, 'w', encoding='utf-8') as fh:
            fh.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        # Last-resort fallback: still avoid a hard-coded public default.
        return secrets.token_hex(32)


def create_app() -> Flask:
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 100  # 100 MB upload cap
    app.config['SECRET_KEY'] = _get_secret_key()
    app.config['BASE_DIR'] = BASE_DIR
    app.config['UPLOAD_DIR'] = os.path.join(BASE_DIR, 'data', 'uploads')
    app.config['OUTPUT_DIR'] = os.path.join(BASE_DIR, 'data', 'outputs')
    app.config['TEMP_DIR'] = os.path.join(BASE_DIR, 'data', 'temp')

    for key in ('UPLOAD_DIR', 'OUTPUT_DIR', 'TEMP_DIR'):
        os.makedirs(app.config[key], exist_ok=True)

    @app.route('/')
    def index():
        return render_template('index.html')

    app.register_blueprint(encode_bp)
    app.register_blueprint(decode_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(contacts_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(testbench_bp)
    return app


app = create_app()
