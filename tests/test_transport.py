"""tests/test_transport.py — hermetic tests for host resolution, TLS provisioning,
and KDF rate limiting.  No real sockets are bound; no real server is started."""

import json
import time

from qrfs._startup import ensure_self_signed_cert, resolve_host
from qrfs.core import ratelimit

# ---------------------------------------------------------------------------
# Host-resolution tests
# ---------------------------------------------------------------------------

def test_default_host_is_loopback():
    """With no flags and no env vars, the resolved host must be 127.0.0.1."""
    assert resolve_host(argv=['qrfs'], env={}) == '127.0.0.1'


def test_lan_flag_resolves_to_all_interfaces():
    """--lan must resolve to 0.0.0.0."""
    assert resolve_host(argv=['qrfs', '--lan'], env={}) == '0.0.0.0'


def test_explicit_host_wins_over_lan(capsys):
    """--host beats --lan; a warning must be printed to stderr."""
    host = resolve_host(argv=['qrfs', '--host', '192.168.1.50', '--lan'], env={})
    assert host == '192.168.1.50'
    captured = capsys.readouterr()
    assert '--lan ignored' in captured.err


def test_env_host_wins_over_lan(monkeypatch):
    """QRFS_HOST beats QRFS_LAN=1."""
    host = resolve_host(argv=['qrfs'], env={'QRFS_HOST': '10.0.0.1', 'QRFS_LAN': '1'})
    assert host == '10.0.0.1'


def test_lan_env_var_resolves_to_all_interfaces():
    """QRFS_LAN=1 with no explicit host must resolve to 0.0.0.0."""
    assert resolve_host(argv=['qrfs'], env={'QRFS_LAN': '1'}) == '0.0.0.0'


def test_explicit_host_via_equals_syntax():
    """--host=<value> syntax must be honoured."""
    assert resolve_host(argv=['qrfs', '--host=172.16.0.1'], env={}) == '172.16.0.1'


# ---------------------------------------------------------------------------
# TLS certificate provisioning tests
# ---------------------------------------------------------------------------

def test_https_flag_generates_cert(tmp_path, monkeypatch):
    """ensure_self_signed_cert creates cert.pem and key.pem on first call."""
    cert_path, key_path = ensure_self_signed_cert(tmp_path, ['127.0.0.1'])

    assert cert_path.exists(), 'cert.pem was not created'
    assert key_path.exists(), 'key.pem was not created'

    # Key must have restricted permissions on POSIX.
    import os
    import stat
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600, f'key.pem mode is {oct(mode)}, expected 0o600'


def test_https_cert_is_reused_on_second_call(tmp_path):
    """ensure_self_signed_cert must reuse an existing, valid cert (mtime unchanged)."""
    cert_path, key_path = ensure_self_signed_cert(tmp_path, ['127.0.0.1'])
    mtime_before = cert_path.stat().st_mtime

    # Small sleep to ensure mtime would differ if the file were rewritten.
    time.sleep(0.05)
    ensure_self_signed_cert(tmp_path, ['127.0.0.1'])
    mtime_after = cert_path.stat().st_mtime

    assert mtime_after == mtime_before, 'cert.pem was regenerated instead of reused'


def test_https_cert_contains_expected_fields(tmp_path):
    """The generated cert must include localhost and 127.0.0.1 in its SANs."""
    import ipaddress

    from cryptography import x509
    from cryptography.x509.extensions import SubjectAlternativeName

    cert_path, _ = ensure_self_signed_cert(tmp_path, ['127.0.0.1'])
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)

    assert 'localhost' in dns_names
    assert ipaddress.ip_address('127.0.0.1') in ip_addrs


# ---------------------------------------------------------------------------
# Rate-limiter unit tests
# ---------------------------------------------------------------------------

class _FakeApp:
    """Minimal Flask-like app context for testing the rate limiter."""
    def __init__(self, testing: bool = False):
        self.config = {'TESTING': testing}


def _push_fake_ctx(monkeypatch, testing: bool = False):
    """Patch current_app and request inside ratelimit so tests run without Flask."""
    fake_app = _FakeApp(testing=testing)
    monkeypatch.setattr(ratelimit, 'current_app', fake_app)  # type: ignore[attr-defined]

    class _FakeRequest:
        remote_addr = '203.0.113.1'

    monkeypatch.setattr(ratelimit, 'request', _FakeRequest())  # type: ignore[attr-defined]


def test_rate_limiter_allows_burst_then_blocks(monkeypatch):
    """5 attempts must be allowed; the 6th must be blocked with HTTP 429."""
    ratelimit._reset()
    _push_fake_ctx(monkeypatch, testing=False)

    for i in range(5):
        result = ratelimit.check_kdf_rate_limit()
        assert result is None, f'Attempt {i + 1} was unexpectedly blocked'

    blocked = ratelimit.check_kdf_rate_limit()
    assert blocked is not None, '6th attempt was not blocked'
    assert blocked.status_code == 429
    data = json.loads(blocked.get_data(as_text=True))
    assert data['error'] == 'too_many_attempts'
    assert 'retry_after' in data
    assert int(blocked.headers['Retry-After']) > 0


def test_rate_limiter_resets_after_window(monkeypatch):
    """After the window expires (mocked), attempts should be allowed again."""
    ratelimit._reset()
    _push_fake_ctx(monkeypatch, testing=False)

    # Exhaust the quota.
    for _ in range(5):
        ratelimit.check_kdf_rate_limit()

    # Move the clock forward by more than the window using a monkeypatch.
    base_time = time.monotonic()
    monkeypatch.setattr(time, 'monotonic', lambda: base_time + ratelimit._WINDOW + 1)

    result = ratelimit.check_kdf_rate_limit()
    assert result is None, 'Attempt after window expired was incorrectly blocked'


def test_rate_limiter_is_noop_in_testing_mode(monkeypatch):
    """When TESTING=True, the rate limiter must always return None."""
    ratelimit._reset()
    _push_fake_ctx(monkeypatch, testing=True)

    for _ in range(20):
        assert ratelimit.check_kdf_rate_limit() is None


def test_rate_limiter_tracks_per_ip(monkeypatch):
    """Different IPs must have independent counters."""
    ratelimit._reset()

    fake_app = _FakeApp(testing=False)
    monkeypatch.setattr(ratelimit, 'current_app', fake_app)

    class _FakeRequestA:
        remote_addr = '198.51.100.1'

    class _FakeRequestB:
        remote_addr = '198.51.100.2'

    # Exhaust quota for IP A.
    monkeypatch.setattr(ratelimit, 'request', _FakeRequestA())
    for _ in range(5):
        ratelimit.check_kdf_rate_limit()
    assert ratelimit.check_kdf_rate_limit() is not None, 'IP A should be blocked'

    # IP B should still be unblocked.
    monkeypatch.setattr(ratelimit, 'request', _FakeRequestB())
    assert ratelimit.check_kdf_rate_limit() is None, 'IP B should not be blocked'
