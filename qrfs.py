#!/usr/bin/env python3
import os
import sys

from qrfs import app


def _env_flag(name: str) -> bool:
    value = (os.environ.get(name) or '').strip().lower()
    return value in {'1', 'true', 'yes', 'on'}


def _parse_arg_value(flag: str) -> str | None:
    prefix = f'{flag}='
    for idx, arg in enumerate(sys.argv[1:], start=1):
        if arg == flag and idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return None


def _env_port(default: int = 5000) -> int:
    raw = _parse_arg_value('--port') or (os.environ.get('QRFS_PORT') or '').strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        return default
    if 1 <= port <= 65535:
        return port
    return default


def _env_host(default: str = '0.0.0.0') -> str:
    raw = _parse_arg_value('--host') or os.environ.get('QRFS_HOST', default)
    raw = (raw or '').strip()
    return raw or default


def main() -> None:
    use_debug = '--debug' in sys.argv or _env_flag('QRFS_DEBUG')
    force_flask_dev = '--flask-dev' in sys.argv or _env_flag('QRFS_FLASK_DEV')
    host = _env_host('0.0.0.0')
    port = _env_port(5000)

    if use_debug:
        try:
            import _multiprocessing  # noqa: F401
        except ImportError:
            use_debug = False

    # In debug mode we deliberately keep Flask's built-in server because it
    # provides the reloader and debugger developers expect.
    if use_debug or force_flask_dev:
        app.run(host=host, port=port, debug=use_debug)
        return

    try:
        from waitress import serve
    except ImportError:
        # Safe fallback: still start the app even if waitress is not installed.
        app.run(host=host, port=port, debug=False)
        return

    serve(app, host=host, port=port)


if __name__ == '__main__':
    main()
