"""Smoke tests verifying the Streamlit app renders and executes flows without exceptions."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from crypto_core import encrypt_and_split, sha256_hex


APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")


def test_app_renders_cleanly_without_exceptions() -> None:
    at = AppTest.from_file(APP_PATH, default_timeout=20)
    at.run()
    assert not at.exception
    assert len(at.tabs) == 3


def test_app_session_decrypt_n_minus_one_and_tamper_flows() -> None:
    at = AppTest.from_file(APP_PATH, default_timeout=20)
    payload = b"Pengujian UI Streamlit CAPSTONE 2026 - Fernet + XOR."
    enc = encrypt_and_split(payload, n=3)

    at.session_state["last_enc"] = {
        "original_filename": "uji.txt",
        "vault_filename": "uji.txt.vault",
        "original_bytes": payload,
        "vault_bytes": enc.vault_bytes,
        "vault_sha256": sha256_hex(enc.vault_bytes),
        "original_sha256": enc.original_sha256,
        "shares": enc.shares,
        "n_shares": 3,
        "original_size": enc.original_size,
        "vault_size": enc.vault_size,
        "expansion_pct": enc.expansion_pct,
        "enc_ms": enc.enc_ms,
        "split_ms": enc.split_ms,
        "ct_entropy": 7.8,
        "share_entropies": [0.99, 0.99, 0.99],
        "mean_corr": 0.01,
    }
    at.run()
    assert not at.exception

    # 1) All 3 shares selected -> recovery succeeds with Hash Match & BER 0.0%.
    dec_btn = [b for b in at.button if "Dekripsi Berkas" in b.label][0]
    dec_btn.click().run()
    assert not at.exception
    assert any("PEMULIHAN BERHASIL" in s.value for s in at.success)

    # 2) Drop 1 share (n-1 test) -> rejected with InvalidToken alert.
    share_ms = at.multiselect[0]
    share_ms.set_value([1, 2]).run()
    dec_btn = [b for b in at.button if "Dekripsi Berkas" in b.label][0]
    dec_btn.click().run()
    assert not at.exception
    assert any("AKSES DITOLAK" in e.value for e in at.error)

    # 3) Restore 3 shares, enable 1-bit tamper -> rejected by HMAC verification.
    at.multiselect[0].set_value([1, 2, 3]).run()
    tamper_cb = [c for c in at.checkbox if "modifikasi 1 bit" in c.label][0]
    tamper_cb.check().run()
    dec_btn = [b for b in at.button if "Dekripsi Berkas" in b.label][0]
    dec_btn.click().run()
    assert not at.exception
    assert any("AKSES DITOLAK" in e.value for e in at.error)
