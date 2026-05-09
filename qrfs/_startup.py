"""qrfs/_startup.py — pure, standalone helpers for host resolution and TLS provisioning.

Kept in a separate module so they can be imported by tests without pulling in
Flask, pyzbar, or any other heavy dependency.
"""

import hashlib
import ipaddress
import os
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Argument / environment helpers
# ---------------------------------------------------------------------------

def _env_flag_from(name: str, env: dict[str, str]) -> bool:
    value = (env.get(name) or '').strip().lower()
    return value in {'1', 'true', 'yes', 'on'}


def _parse_arg_value_from(flag: str, argv: list[str]) -> str | None:
    prefix = f'{flag}='
    for idx, arg in enumerate(argv[1:], start=1):
        if arg == flag and idx + 1 < len(argv):
            return argv[idx + 1]
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return None


# ---------------------------------------------------------------------------
# Host resolution
# ---------------------------------------------------------------------------

def resolve_host(argv: list[str], env: dict[str, str]) -> str:
    """Return the effective bind host, applying precedence rules.

    Precedence (strongest first):

    1. ``--host <value>`` in *argv*.
    2. ``QRFS_HOST`` in *env*.
    3. ``--lan`` in *argv* or ``QRFS_LAN=1`` in *env*  →  ``0.0.0.0``.
    4. Default  →  ``127.0.0.1``.

    If both an explicit host (rule 1 or 2) and ``--lan`` are present, the
    explicit host wins and a warning is printed to stderr.
    """
    explicit_host = _parse_arg_value_from('--host', argv)
    env_host = env.get('QRFS_HOST', '').strip()
    use_lan = '--lan' in argv or _env_flag_from('QRFS_LAN', env)

    if explicit_host:
        if use_lan:
            print('--lan ignored because --host was provided explicitly', file=sys.stderr)
        return explicit_host

    if env_host:
        if use_lan:
            print('--lan ignored because QRFS_HOST was provided explicitly', file=sys.stderr)
        return env_host

    if use_lan:
        return '0.0.0.0'

    return '127.0.0.1'


# ---------------------------------------------------------------------------
# TLS certificate provisioning
# ---------------------------------------------------------------------------

def ensure_self_signed_cert(cert_dir: Path, hostnames: list[str]) -> tuple[Path, Path]:
    """Provision a self-signed TLS certificate, reusing it when still valid.

    Creates *cert_dir* if it does not exist.  The key is stored with mode
    ``0o600``.  Regenerates the cert if it expires within 30 days.

    Args:
        cert_dir:  Directory where ``cert.pem`` and ``key.pem`` are stored.
        hostnames: List of hostnames/IPs for the Subject Alternative Names.

    Returns:
        ``(cert_path, key_path)`` as ``Path`` objects.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / 'cert.pem'
    key_path = cert_dir / 'key.pem'

    # Reuse if both files exist and the cert is not expiring within 30 days.
    if cert_path.exists() and key_path.exists():
        try:
            cert_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)
            cutoff = datetime.now(tz=UTC) + timedelta(days=30)
            if cert.not_valid_after_utc > cutoff:
                return cert_path, key_path
        except Exception:
            pass  # Fall through and regenerate.

    # Generate Ed25519 private key (fast; no per-operation randomness needed).
    private_key = Ed25519PrivateKey.generate()

    # Build Subject Alternative Names from the hostnames list.
    san_entries: list[x509.GeneralName] = []
    for name in hostnames:
        try:
            ip_obj = ipaddress.ip_address(name)
            san_entries.append(x509.IPAddress(ip_obj))
        except ValueError:
            san_entries.append(x509.DNSName(name))

    # Always include localhost / 127.0.0.1 in the SAN.
    loopback_dns = x509.DNSName('localhost')
    loopback_ip = x509.IPAddress(ipaddress.ip_address('127.0.0.1'))
    if loopback_dns not in san_entries:
        san_entries.insert(0, loopback_dns)
    if loopback_ip not in san_entries:
        san_entries.insert(1, loopback_ip)

    # Self-signed certificate (notBefore = now, notAfter = now + 825 days).
    now = datetime.now(tz=UTC)
    cn = hostnames[0] if hostnames else 'localhost'
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,  # Ed25519 does not perform key encipherment
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        # Ed25519 signs with algorithm=None (the hash is implicit in the key type).
        .sign(private_key, algorithm=None)
    )

    # Serialise key with restricted permissions.
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    key_path.write_bytes(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    cert_path.write_bytes(cert_pem)

    return cert_path, key_path


# ---------------------------------------------------------------------------
# Certificate fingerprint
# ---------------------------------------------------------------------------

def cert_fingerprint(cert_path: Path) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate as ``AA:BB:...`` hex."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    der = cert.public_bytes(serialization.Encoding.DER)
    sha256 = hashlib.sha256(der).digest()
    return ':'.join(f'{b:02X}' for b in sha256)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def is_loopback(host: str) -> bool:
    """Return ``True`` if *host* is a loopback address or hostname."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == 'localhost'


def detect_lan_ips() -> list[str]:
    """Return the machine's non-loopback IPv4 addresses (best-effort)."""
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        return [a for a in addrs if not ipaddress.ip_address(a).is_loopback]
    except Exception:
        return []
