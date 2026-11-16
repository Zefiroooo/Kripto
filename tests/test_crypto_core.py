"""Tests for Fernet + XOR Secret Sharing core logic and security evaluation metrics."""

from __future__ import annotations

import os
import pytest

from crypto_core import (
    InvalidToken,
    MASTER_KEY_BYTES,
    combine_and_decrypt,
    encrypt_and_split,
    parse_share_input,
    sha256_hex,
    tamper_vault_byte,
    xor_combine,
    xor_split,
)
from metrics import (
    compute_ber_percent,
    compute_ciphertext_entropy,
    compute_share_bit_entropies,
    compute_share_correlations,
    run_single_payload_benchmark,
    verify_n_minus_one_blocked,
)


def test_xor_split_and_combine_roundtrip() -> None:
    secret = os.urandom(MASTER_KEY_BYTES)
    shares = xor_split(secret, n=3)
    assert len(shares) == 3
    assert all(len(s) == MASTER_KEY_BYTES for s in shares)
    assert xor_combine(shares) == secret


def test_xor_validation_errors() -> None:
    with pytest.raises(ValueError):
        xor_split(b"", n=3)
    with pytest.raises(ValueError):
        xor_split(os.urandom(32), n=1)
    with pytest.raises(ValueError):
        xor_combine([])
    with pytest.raises(ValueError):
        xor_combine([b"\x01" * 32, b"\x02" * 16])


@pytest.mark.parametrize("size", [1, 37, 1024, 65536])
def test_encrypt_decrypt_roundtrip_hash_and_ber(size: int) -> None:
    payload = os.urandom(size)
    enc = encrypt_and_split(payload, n=3)
    assert enc.vault_bytes.startswith(b"gAAAAAB")
    assert enc.original_sha256 == sha256_hex(payload)

    dec = combine_and_decrypt(enc.vault_bytes, enc.shares)
    assert dec.recovered_bytes == payload
    assert dec.recovered_sha256 == enc.original_sha256
    assert compute_ber_percent(payload, dec.recovered_bytes) == 0.0


def test_n_minus_one_shares_always_blocked() -> None:
    payload = b"Dokumen rahasia CAPSTONE 2026 - uji keamanan n-1 share."
    enc = encrypt_and_split(payload, n=3)

    assert verify_n_minus_one_blocked(enc.vault_bytes, enc.shares) is True
    for drop_idx in range(3):
        subset = [s for idx, s in enumerate(enc.shares) if idx != drop_idx]
        with pytest.raises(InvalidToken):
            combine_and_decrypt(enc.vault_bytes, subset)


def test_tampered_vault_rejected_by_hmac() -> None:
    payload = b"Data sensitif yang dilindungi HMAC-SHA256 Fernet."
    enc = encrypt_and_split(payload, n=3)
    tampered = tamper_vault_byte(enc.vault_bytes)
    assert tampered != enc.vault_bytes

    with pytest.raises(InvalidToken):
        combine_and_decrypt(tampered, enc.shares)


def test_parse_share_input_binary_and_hex() -> None:
    raw = os.urandom(MASTER_KEY_BYTES)
    assert parse_share_input(raw_bytes=raw) == raw

    hex_str = raw.hex()
    assert parse_share_input(hex_text=hex_str) == raw
    assert parse_share_input(raw_bytes=hex_str.encode("ascii")) == raw

    with pytest.raises(ValueError):
        parse_share_input(hex_text="not-hex")
    with pytest.raises(ValueError):
        parse_share_input(raw_bytes=b"too-short")


def test_metrics_entropy_correlation_and_single_benchmark() -> None:
    payload = os.urandom(16 * 1024)
    enc = encrypt_and_split(payload, n=3)

    ct_ent = compute_ciphertext_entropy(enc.vault_bytes)
    assert 7.5 < ct_ent <= 8.0

    sh_ents = compute_share_bit_entropies(enc.shares)
    assert len(sh_ents) == 3
    assert all(0.85 <= e <= 1.0 for e in sh_ents)

    mean_corr, pairs = compute_share_correlations(enc.shares)
    assert len(pairs) == 3
    assert -1.0 <= mean_corr <= 1.0

    row = run_single_payload_benchmark("4 KB", 4096, n=3)
    assert row["Hash Match"] is True
    assert row["BER (%)"] == 0.0
    assert row["n-1 Blocked"] is True
