from pathlib import Path

import pytest

from qrfs.__main__ import _run_encrypt_password_cli
from qrfs.core.crypto_utils import decrypt_file_payload_password, inspect_crypto_blob


def test_encrypt_password_cli_accepts_kdf_profile_and_overrides(tmp_path: Path) -> None:
    payload = b"QFSP\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    input_path = tmp_path / "input.qfsp"
    output_path = tmp_path / "output.qfsc"
    input_path.write_bytes(payload)

    rc = _run_encrypt_password_cli(
        [
            "--in",
            str(input_path),
            "--out",
            str(output_path),
            "--password",
            "testpassword14chars!",
            "--kdf-profile",
            "interactive",
            "--kdf-memory",
            "262144",
            "--kdf-time",
            "4",
            "--kdf-parallel",
            "1",
        ]
    )

    assert rc == 0
    encrypted = output_path.read_bytes()
    info = inspect_crypto_blob(encrypted)
    assert info["mode"] == "password"
    assert info["kdf_memory_kib"] == 262144
    assert info["kdf_time_cost"] == 4
    assert info["kdf_parallelism"] == 1
    decrypted, _ = decrypt_file_payload_password(encrypted, "testpassword14chars!")
    assert decrypted == payload


def test_encrypt_password_cli_rejects_invalid_kdf_ranges(tmp_path: Path) -> None:
    payload = b"QFSP\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    input_path = tmp_path / "input.qfsp"
    output_path = tmp_path / "output.qfsc"
    input_path.write_bytes(payload)

    with pytest.raises(ValueError, match="KDF memory must be between 8 and 4194304"):
        _run_encrypt_password_cli(
            [
                "--in",
                str(input_path),
                "--out",
                str(output_path),
                "--password",
                "testpassword14chars!",
                "--kdf-memory",
                "7",
            ]
        )
