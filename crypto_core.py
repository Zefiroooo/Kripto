"""Core cryptographic logic combining Fernet authenticated encryption and n-of-n XOR Secret Sharing."""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass

import numpy as np
from cryptography.fernet import Fernet, InvalidToken


MASTER_KEY_BYTES = 32


@dataclass(frozen=True)
class EncryptionResult:
    """Outputs and timings produced by encrypting a file and splitting its key."""

    vault_bytes: bytes
    raw_key: bytes
    shares: list[bytes]
    original_sha256: str
    original_size: int
    vault_size: int
    expansion_pct: float
    enc_ms: float
    split_ms: float


@dataclass(frozen=True)
class DecryptionResult:
    """Outputs and timings produced by combining shares and decrypting a vault."""

    recovered_bytes: bytes
    recovered_sha256: str
    comb_ms: float
    dec_ms: float


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 hex digest for a byte payload."""
    return hashlib.sha256(data).hexdigest()


def xor_split(secret_bytes: bytes, n: int = 3) -> list[bytes]:
    """Split secret_bytes into n independent shares using n-of-n bitwise XOR."""
    if not secret_bytes:
        raise ValueError("Kunci rahasia tidak boleh kosong.")
    if n < 2:
        raise ValueError("Jumlah share minimal adalah 2.")

    secret_arr = np.frombuffer(secret_bytes, dtype=np.uint8)
    shares: list[bytes] = []
    xor_accum = secret_arr.copy()
    for _ in range(n - 1):
        rand_share = np.frombuffer(os.urandom(len(secret_bytes)), dtype=np.uint8)
        shares.append(rand_share.tobytes())
        xor_accum = np.bitwise_xor(xor_accum, rand_share)
    shares.append(xor_accum.tobytes())
    return shares


def xor_combine(shares: list[bytes]) -> bytes:
    """Reconstruct secret bytes by XOR-combining all provided shares."""
    if not shares:
        raise ValueError("Minimal satu share harus diberikan.")

    expected_len = len(shares[0])
    if expected_len == 0:
        raise ValueError("Share tidak boleh kosong.")

    result = np.zeros(expected_len, dtype=np.uint8)
    for idx, share in enumerate(shares, start=1):
        if len(share) != expected_len:
            raise ValueError(
                f"Panjang share ke-{idx} ({len(share)} byte) tidak sesuai "
                f"dengan share pertama ({expected_len} byte)."
            )
        result = np.bitwise_xor(result, np.frombuffer(share, dtype=np.uint8))
    return result.tobytes()


def raw_key_to_fernet_key(raw_key: bytes) -> bytes:
    """Encode a 32-byte raw master key as a URL-safe Base64 Fernet key."""
    if len(raw_key) != MASTER_KEY_BYTES:
        raise ValueError(
            f"Kunci master harus berukuran {MASTER_KEY_BYTES} byte, "
            f"diterima {len(raw_key)} byte."
        )
    return base64.urlsafe_b64encode(raw_key)


def parse_share_input(raw_bytes: bytes | None = None, hex_text: str | None = None) -> bytes:
    """Parse a share from either raw 32-byte binary, ASCII hex file content, or hex text."""
    if hex_text is not None:
        cleaned = "".join(hex_text.split())
        if not cleaned:
            raise ValueError("Teks hex share masih kosong.")
        try:
            parsed = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("Format hex share tidak valid.") from exc
        if len(parsed) != MASTER_KEY_BYTES:
            raise ValueError(
                f"Share hasil dekode hex harus {MASTER_KEY_BYTES} byte "
                f"({MASTER_KEY_BYTES * 2} karakter hex), diterima {len(parsed)} byte."
            )
        return parsed

    if raw_bytes is None:
        raise ValueError("Data share tidak diberikan.")

    if len(raw_bytes) == MASTER_KEY_BYTES:
        return raw_bytes

    # Also accept .key files saved as UTF-8 hex text.
    try:
        decoded_text = raw_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Ukuran berkas share harus {MASTER_KEY_BYTES} byte, diterima {len(raw_bytes)} byte."
        ) from exc

    cleaned = "".join(decoded_text.split())
    if len(cleaned) == MASTER_KEY_BYTES * 2:
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("Berkas share tidak berformat biner 32 byte maupun hex valid.") from exc

    raise ValueError(
        f"Ukuran berkas share tidak valid ({len(raw_bytes)} byte; "
        f"harus {MASTER_KEY_BYTES} byte biner atau {MASTER_KEY_BYTES * 2} karakter hex)."
    )


def encrypt_and_split(raw_data: bytes, n: int = 3) -> EncryptionResult:
    """Encrypt raw_data using Fernet and split the 32-byte master key into n XOR shares."""
    raw_key = os.urandom(MASTER_KEY_BYTES)
    fernet_key = raw_key_to_fernet_key(raw_key)

    t0 = time.perf_counter()
    vault_bytes = Fernet(fernet_key).encrypt(raw_data)
    enc_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    shares = xor_split(raw_key, n=n)
    split_ms = (time.perf_counter() - t1) * 1000.0

    orig_size = len(raw_data)
    vault_size = len(vault_bytes)
    expansion_pct = ((vault_size - orig_size) / orig_size * 100.0) if orig_size > 0 else 0.0

    return EncryptionResult(
        vault_bytes=vault_bytes,
        raw_key=raw_key,
        shares=shares,
        original_sha256=sha256_hex(raw_data),
        original_size=orig_size,
        vault_size=vault_size,
        expansion_pct=expansion_pct,
        enc_ms=enc_ms,
        split_ms=split_ms,
    )


def combine_and_decrypt(vault_bytes: bytes, shares: list[bytes]) -> DecryptionResult:
    """Combine XOR shares, reconstruct the Fernet key, and verify-before-decrypt the vault."""
    t0 = time.perf_counter()
    recovered_raw_key = xor_combine(shares)
    comb_ms = (time.perf_counter() - t0) * 1000.0

    fernet_key = raw_key_to_fernet_key(recovered_raw_key)

    t1 = time.perf_counter()
    recovered_bytes = Fernet(fernet_key).decrypt(vault_bytes)
    dec_ms = (time.perf_counter() - t1) * 1000.0

    return DecryptionResult(
        recovered_bytes=recovered_bytes,
        recovered_sha256=sha256_hex(recovered_bytes),
        comb_ms=comb_ms,
        dec_ms=dec_ms,
    )


def tamper_vault_byte(vault_bytes: bytes, offset: int | None = None) -> bytes:
    """Flip one bit inside a Fernet vault token to simulate ciphertext/HMAC tampering."""
    if not vault_bytes:
        raise ValueError("Berkas .vault kosong.")
    buf = bytearray(vault_bytes)
    # Flip a bit near the middle of the token (ciphertext or HMAC area).
    idx = len(buf) // 2 if offset is None else offset % len(buf)
    buf[idx] ^= 0x01
    return bytes(buf)


__all__ = [
    "MASTER_KEY_BYTES",
    "EncryptionResult",
    "DecryptionResult",
    "InvalidToken",
    "sha256_hex",
    "xor_split",
    "xor_combine",
    "raw_key_to_fernet_key",
    "parse_share_input",
    "encrypt_and_split",
    "combine_and_decrypt",
    "tamper_vault_byte",
]
