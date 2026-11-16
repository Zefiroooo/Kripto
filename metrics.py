"""Security evaluation metrics, 10-payload benchmark runner, and Matplotlib chart builders."""

from __future__ import annotations

import base64
import os
from typing import Callable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.spatial.distance import hamming
from scipy.stats import entropy, pearsonr

from crypto_core import (
    InvalidToken,
    combine_and_decrypt,
    encrypt_and_split,
)


PAYLOAD_SPECS: list[tuple[str, int]] = [
    ("1 KB", 1 * 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("500 KB", 500 * 1024),
    ("1 MB", 1 * 1024 * 1024),
    ("5 MB", 5 * 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
    ("20 MB", 20 * 1024 * 1024),
    ("35 MB", 35 * 1024 * 1024),
    ("50 MB", 50 * 1024 * 1024),
]


def compute_ber_percent(
    original: bytes,
    recovered: bytes,
    chunk_bytes: int = 2 * 1024 * 1024,
) -> float:
    """Compute Bit Error Rate (%) via scipy.spatial.distance.hamming in bounded-memory chunks."""
    if len(original) != len(recovered):
        max_len = max(len(original), len(recovered))
        if max_len == 0:
            return 0.0
        original = original.ljust(max_len, b"\x00")
        recovered = recovered.ljust(max_len, b"\x00")

    total_bits = len(original) * 8
    if total_bits == 0:
        return 0.0

    error_bits = 0.0
    for offset in range(0, len(original), chunk_bytes):
        end = offset + chunk_bytes
        a_bits = np.unpackbits(np.frombuffer(original[offset:end], dtype=np.uint8))
        b_bits = np.unpackbits(np.frombuffer(recovered[offset:end], dtype=np.uint8))
        error_bits += float(hamming(a_bits, b_bits)) * len(a_bits)
    return (error_bits / total_bits) * 100.0


def compute_ciphertext_entropy(vault_bytes: bytes) -> float:
    """Compute Shannon entropy (bit/byte, max 8.0) on decoded binary Fernet token bytes."""
    if not vault_bytes:
        return 0.0
    try:
        raw_ct = base64.urlsafe_b64decode(vault_bytes)
    except Exception:
        raw_ct = vault_bytes

    arr = np.frombuffer(raw_ct, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    return float(entropy(counts, base=2))


def compute_share_bit_entropies(shares: list[bytes]) -> list[float]:
    """Compute per-share binary Shannon entropy (bit/bit, max 1.0)."""
    results: list[float] = []
    for share in shares:
        bits = np.unpackbits(np.frombuffer(share, dtype=np.uint8))
        counts = np.bincount(bits, minlength=2)
        results.append(float(entropy(counts, base=2)))
    return results


def compute_share_correlations(shares: list[bytes]) -> tuple[float, list[tuple[str, float]]]:
    """Compute pairwise Pearson correlation across 32-byte share vectors and their mean."""
    pairs: list[tuple[str, float]] = []
    for i in range(len(shares)):
        for j in range(i + 1, len(shares)):
            a = np.frombuffer(shares[i], dtype=np.uint8).astype(np.float64)
            b = np.frombuffer(shares[j], dtype=np.uint8).astype(np.float64)
            if np.std(a) == 0.0 or np.std(b) == 0.0:
                corr = 0.0
            else:
                corr = float(pearsonr(a, b).statistic)
            pairs.append((f"Share {i + 1} vs Share {j + 1}", corr))

    mean_corr = float(np.mean([val for _, val in pairs])) if pairs else 0.0
    return mean_corr, pairs


def verify_n_minus_one_blocked(vault_bytes: bytes, shares: list[bytes]) -> bool:
    """Verify that supplying only n-1 shares fails decryption with InvalidToken."""
    if len(shares) < 2:
        return False
    try:
        combine_and_decrypt(vault_bytes, shares[:-1])
        return False
    except InvalidToken:
        return True


def run_single_payload_benchmark(label: str, size_bytes: int, n: int = 3) -> dict[str, object]:
    """Execute full encrypt-split-combine-decrypt and security/performance evaluation for one payload."""
    payload = os.urandom(size_bytes)
    enc_res = encrypt_and_split(payload, n=n)
    dec_res = combine_and_decrypt(enc_res.vault_bytes, enc_res.shares)

    hash_match = enc_res.original_sha256 == dec_res.recovered_sha256
    ber_pct = compute_ber_percent(payload, dec_res.recovered_bytes)
    n_minus_1_blocked = verify_n_minus_one_blocked(enc_res.vault_bytes, enc_res.shares)
    ct_entropy = compute_ciphertext_entropy(enc_res.vault_bytes)
    share_bit_entropy = float(np.mean(compute_share_bit_entropies(enc_res.shares)))
    mean_corr, pair_corrs = compute_share_correlations(enc_res.shares)

    total_ms = enc_res.enc_ms + enc_res.split_ms + dec_res.comb_ms + dec_res.dec_ms

    row: dict[str, object] = {
        "Payload": label,
        "Ukuran Asli (Byte)": enc_res.original_size,
        "Ukuran Vault (Byte)": enc_res.vault_size,
        "Ekspansi (%)": round(enc_res.expansion_pct, 4),
        "Hash Match": bool(hash_match),
        "BER (%)": round(ber_pct, 6),
        "n-1 Blocked": bool(n_minus_1_blocked),
        "Entropi Ciphertext (bit/byte)": round(ct_entropy, 4),
        "Entropi Bit Share": round(share_bit_entropy, 4),
        "Korelasi Antar Share (Mean)": round(mean_corr, 4),
        "Enc (ms)": round(enc_res.enc_ms, 3),
        "Split (ms)": round(enc_res.split_ms, 4),
        "Comb (ms)": round(dec_res.comb_ms, 4),
        "Dec (ms)": round(dec_res.dec_ms, 3),
        "Total (ms)": round(total_ms, 3),
    }
    for pair_name, pair_val in pair_corrs:
        row[f"Corr {pair_name}"] = round(pair_val, 4)
    return row


def run_full_benchmark(
    n: int = 3,
    payload_specs: list[tuple[str, int]] | None = None,
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> pd.DataFrame:
    """Run automated benchmark across all configured payload sizes and return a DataFrame."""
    specs = payload_specs if payload_specs is not None else PAYLOAD_SPECS
    rows: list[dict[str, object]] = []
    total = len(specs)
    for idx, (label, size_bytes) in enumerate(specs, start=1):
        if progress_callback is not None:
            progress_callback(idx - 1, total, f"Menguji payload {label} ({idx}/{total})...")
        rows.append(run_single_payload_benchmark(label=label, size_bytes=size_bytes, n=n))
    if progress_callback is not None:
        progress_callback(total, total, "Pengujian seluruh payload selesai.")
    return pd.DataFrame(rows)


def build_benchmark_figures(df: pd.DataFrame) -> dict[str, plt.Figure]:
    """Generate clean Matplotlib figures summarizing timing, entropy, correlation, and expansion."""
    labels = df["Payload"].tolist()
    x = np.arange(len(labels))

    # 1. Processing Time per Stage
    fig_time, ax_time = plt.subplots(figsize=(9.5, 4.4), dpi=150)
    ax_time.plot(x, df["Enc (ms)"], marker="o", linewidth=2, label="Fernet Encrypt (ms)")
    ax_time.plot(x, df["Dec (ms)"], marker="s", linewidth=2, label="Fernet Decrypt (ms)")
    ax_time.plot(x, df["Split (ms)"], marker="^", linestyle="--", linewidth=1.8, label="XOR Split (ms)")
    ax_time.plot(x, df["Comb (ms)"], marker="v", linestyle="--", linewidth=1.8, label="XOR Combine (ms)")
    ax_time.set_title("Waktu Proses per Tahap terhadap Ukuran Payload", fontweight="bold")
    ax_time.set_xlabel("Ukuran Payload")
    ax_time.set_ylabel("Waktu (ms)")
    ax_time.set_xticks(x)
    ax_time.set_xticklabels(labels, rotation=25)
    ax_time.grid(True, linestyle=":", alpha=0.6)
    ax_time.legend()
    fig_time.tight_layout()

    # 2. Entropy: Ciphertext Byte Entropy & Share Bit Entropy
    fig_ent, (ax_ct, ax_sh) = plt.subplots(1, 2, figsize=(10.5, 4.2), dpi=150)
    ax_ct.plot(x, df["Entropi Ciphertext (bit/byte)"], marker="o", color="#1f77b4", linewidth=2)
    ax_ct.axhline(8.0, color="#d62728", linestyle="--", linewidth=1.2, label="Batas Ideal (8.0)")
    ax_ct.set_title("Entropi Ciphertext (bit/byte)", fontweight="bold")
    ax_ct.set_xlabel("Ukuran Payload")
    ax_ct.set_ylabel("Entropi (bit/byte)")
    ax_ct.set_xticks(x)
    ax_ct.set_xticklabels(labels, rotation=35)
    ct_min = float(df["Entropi Ciphertext (bit/byte)"].min())
    ax_ct.set_ylim(min(7.5, ct_min - 0.1), 8.05)
    ax_ct.grid(True, linestyle=":", alpha=0.6)
    ax_ct.legend()

    ax_sh.plot(x, df["Entropi Bit Share"], marker="s", color="#2ca02c", linewidth=2)
    ax_sh.axhline(1.0, color="#d62728", linestyle="--", linewidth=1.2, label="Batas Ideal (1.0)")
    ax_sh.set_title("Rata-rata Entropi Bit Share", fontweight="bold")
    ax_sh.set_xlabel("Ukuran Payload")
    ax_sh.set_ylabel("Entropi (bit/bit)")
    ax_sh.set_xticks(x)
    ax_sh.set_xticklabels(labels, rotation=35)
    sh_min = float(df["Entropi Bit Share"].min())
    ax_sh.set_ylim(min(0.95, sh_min - 0.02), 1.01)
    ax_sh.grid(True, linestyle=":", alpha=0.6)
    ax_sh.legend()
    fig_ent.tight_layout()

    # 3. Correlation Across Shares
    fig_corr, ax_corr = plt.subplots(figsize=(9.5, 4.0), dpi=150)
    corr_cols = [c for c in df.columns if c.startswith("Corr Share ")]
    for col in corr_cols:
        ax_corr.plot(x, df[col], marker="o", alpha=0.75, linewidth=1.5, label=col.replace("Corr ", ""))
    ax_corr.plot(
        x,
        df["Korelasi Antar Share (Mean)"],
        marker="D",
        color="#111827",
        linewidth=2.2,
        label="Rata-rata Korelasi",
    )
    ax_corr.axhline(0.0, color="#dc2626", linestyle="--", linewidth=1.2, label="Ideal (0.0)")
    ax_corr.set_title("Independensi Share: Korelasi Pearson Antar Share", fontweight="bold")
    ax_corr.set_xlabel("Ukuran Payload")
    ax_corr.set_ylabel("Koefisien Korelasi Pearson (r)")
    ax_corr.set_xticks(x)
    ax_corr.set_xticklabels(labels, rotation=25)
    corr_vals = df[corr_cols + ["Korelasi Antar Share (Mean)"]].to_numpy(dtype=float)
    max_corr = float(np.max(np.abs(corr_vals))) if corr_vals.size > 0 else 0.5
    corr_lim = max(0.6, min(1.05, max_corr + 0.12))
    ax_corr.set_ylim(-corr_lim, corr_lim)
    ax_corr.grid(True, linestyle=":", alpha=0.6)
    ax_corr.legend(ncol=2, fontsize=8.5)
    fig_corr.tight_layout()

    # 4. Size Expansion (%)
    fig_exp, ax_exp = plt.subplots(figsize=(9.5, 3.8), dpi=150)
    ax_exp.bar(x, df["Ekspansi (%)"], color="#0ea5e9", alpha=0.85, label="Ekspansi Aktual (%)")
    ax_exp.axhline(33.33, color="#dc2626", linestyle="--", linewidth=1.3, label="Asimtot Base64 (~33.33%)")
    ax_exp.set_title("Ekspansi Ukuran Berkas Terenkripsi (.vault)", fontweight="bold")
    ax_exp.set_xlabel("Ukuran Payload")
    ax_exp.set_ylabel("Ekspansi (%)")
    ax_exp.set_xticks(x)
    ax_exp.set_xticklabels(labels, rotation=25)
    ax_exp.grid(True, axis="y", linestyle=":", alpha=0.6)
    ax_exp.legend()
    fig_exp.tight_layout()

    return {
        "timing": fig_time,
        "entropy": fig_ent,
        "correlation": fig_corr,
        "expansion": fig_exp,
    }


__all__ = [
    "PAYLOAD_SPECS",
    "compute_ber_percent",
    "compute_ciphertext_entropy",
    "compute_share_bit_entropies",
    "compute_share_correlations",
    "verify_n_minus_one_blocked",
    "run_single_payload_benchmark",
    "run_full_benchmark",
    "build_benchmark_figures",
]
