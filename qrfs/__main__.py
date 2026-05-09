#!/usr/bin/env python3
"""QRFS entry point — supports ``python -m qrfs`` and the installed console script.

All CLI flags and environment variables:

  --debug        Enable Flask debug mode (reloader + debugger).
  --flask-dev    Force Flask development server even without --debug.
  --host=ADDR    Override listen address (default: 127.0.0.1).
  --port=N       Override listen port (default: 5000).
  --lan          Bind to 0.0.0.0 (all interfaces).  Shorthand for --host 0.0.0.0.
  --https        Enable TLS.  Auto-generates a self-signed cert on first run.
  --cert=PATH    Path to a PEM certificate file (requires --key).
  --key=PATH     Path to a PEM private-key file (requires --cert).

Corresponding environment variables:
  QRFS_DEBUG, QRFS_FLASK_DEV, QRFS_HOST, QRFS_PORT,
  QRFS_LAN, QRFS_HTTPS, QRFS_CERT, QRFS_KEY

Host-resolution precedence (strongest first):
  1. Explicit --host value on the command line.
  2. QRFS_HOST environment variable.
  3. --lan / QRFS_LAN=1  ->  0.0.0.0.
  4. Default  ->  127.0.0.1.

HTTPS notes:
  When --https is set without --cert/--key, QRFS auto-generates a self-signed
  certificate under data/tls/ and reuses it on subsequent runs (regenerated if
  it expires within 30 days).  The SHA-256 fingerprint is printed at startup
  so users can pin it manually on remote devices.

  Because waitress does not support TLS natively, --https always uses Flask's
  built-in server with ssl_context.  This is intentional and documented here.
"""

import os
import ssl
import sys
from pathlib import Path

# Pure helpers (no Flask / heavy deps) — importable without loading the full app.
from qrfs._startup import (
    _env_flag_from,
    _parse_arg_value_from,
    cert_fingerprint,
    detect_lan_ips,
    ensure_self_signed_cert,
    is_loopback,
    resolve_host,
)


def _env_flag(name: str) -> bool:
    return _env_flag_from(name, dict(os.environ))


def _parse_arg_value(flag: str) -> str | None:
    return _parse_arg_value_from(flag, sys.argv)


def _env_port(default: int = 5000) -> int:
    raw = _parse_arg_value("--port") or (os.environ.get("QRFS_PORT") or "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        return default
    if 1 <= port <= 65535:
        return port
    return default


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------


def _print_banner(host: str, port: int, use_https: bool, cert_path: Path | None) -> None:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}"

    if use_https and cert_path is not None:
        fingerprint = cert_fingerprint(cert_path)
        print(f"[QRFS] Listening on {url}  (self-signed cert)", file=sys.stderr)
        print(f"[QRFS] Cert SHA256 fingerprint: {fingerprint}", file=sys.stderr)
        if not is_loopback(host):
            print("[QRFS] Pin this fingerprint on remote devices to detect MITM.", file=sys.stderr)
        else:
            print(
                "[QRFS] Reachable only from this device. Use --lan to expose on the network.",
                file=sys.stderr,
            )
    elif is_loopback(host):
        print(f"[QRFS] Listening on {url}", file=sys.stderr)
        print(
            "[QRFS] Reachable only from this device. Use --lan to expose on the network.",
            file=sys.stderr,
        )
    else:
        print(f"[QRFS] WARNING: Listening on {url} (all interfaces, plain HTTP).", file=sys.stderr)
        print(  # noqa: E501
            "[QRFS] WARNING: Anyone on this network can read passwords and uploaded files.",
            file=sys.stderr,
        )
        print(
            "[QRFS] WARNING: For untrusted networks, add --https or stay on the default 127.0.0.1.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    # Deferred import so that importing this module for its pure helpers does
    # not trigger the full qrfs package (Flask app, routes, pyzbar …).
    from qrfs import app

    use_debug = "--debug" in sys.argv or _env_flag("QRFS_DEBUG")
    force_flask_dev = "--flask-dev" in sys.argv or _env_flag("QRFS_FLASK_DEV")
    use_https = "--https" in sys.argv or _env_flag("QRFS_HTTPS")

    host = resolve_host(sys.argv, dict(os.environ))
    port = _env_port(5000)

    # --cert / --key override the auto-generated self-signed cert.
    cert_arg = _parse_arg_value("--cert") or os.environ.get("QRFS_CERT", "").strip() or None
    key_arg = _parse_arg_value("--key") or os.environ.get("QRFS_KEY", "").strip() or None

    cert_path: Path | None = None
    key_path: Path | None = None

    if use_https:
        if cert_arg and key_arg:
            cert_path = Path(cert_arg)
            key_path = Path(key_arg)
        else:
            # Auto-generate a self-signed cert under data/tls/.
            base_dir = Path(__file__).parent.parent  # repo root
            tls_dir = base_dir / "data" / "tls"

            # Collect SAN hostnames: always localhost + 127.0.0.1 (added by
            # ensure_self_signed_cert); also include LAN IPs when binding to
            # all interfaces.
            san_hostnames: list[str] = [] if host in ("0.0.0.0", "::") else [host]
            if not is_loopback(host):
                san_hostnames.extend(detect_lan_ips())

            cert_path, key_path = ensure_self_signed_cert(tls_dir, san_hostnames)

    _print_banner(host, port, use_https, cert_path)

    if use_debug:
        try:
            import _multiprocessing  # noqa: F401
        except ImportError:
            use_debug = False

    # When HTTPS is requested, always use Flask's built-in server with
    # ssl_context because waitress does not support TLS natively.
    # This is intentional: --https is an opt-in, not the high-throughput path.
    if use_https:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        assert cert_path is not None and key_path is not None  # guaranteed above
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        app.run(host=host, port=port, debug=use_debug, ssl_context=ssl_ctx)
        return

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


if __name__ == "__main__":
    main()
