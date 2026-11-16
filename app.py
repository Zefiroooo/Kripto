"""Streamlit interactive prototype for CAPSTONE 2026: Fernet + n-of-n XOR Secret Sharing."""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from crypto_core import (
    InvalidToken,
    combine_and_decrypt,
    encrypt_and_split,
    parse_share_input,
    sha256_hex,
    tamper_vault_byte,
)
from metrics import (
    PAYLOAD_SPECS,
    build_benchmark_figures,
    compute_ber_percent,
    compute_ciphertext_entropy,
    compute_share_bit_entropies,
    compute_share_correlations,
    run_full_benchmark,
)


CACHED_BENCHMARK_CSV = Path(__file__).parent / "outputs" / "benchmark_10_payload.csv"


def format_size(num_bytes: int) -> str:
    """Format byte count into human-readable units."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def preview_content(data: bytes, max_chars: int = 360) -> tuple[str, str]:
    """Return (label, preview_text) safely for UTF-8 text or binary payloads."""
    sample = data[:4096]
    try:
        text = sample.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text[:120]):
            snippet = text[:max_chars]
            if len(data) > max_chars:
                snippet += "\n..."
            return "Pratinjau Teks (UTF-8)", snippet
    except UnicodeDecodeError:
        pass

    hex_str = " ".join(f"{b:02X}" for b in data[:64])
    if len(data) > 64:
        hex_str += " ..."
    return "Pratinjau Biner (64 Byte Pertama dalam Hex)", hex_str


def strip_vault_suffix(filename: str) -> str:
    """Recover original filename from a .vault filename."""
    if filename.lower().endswith(".vault") and len(filename) > 6:
        return filename[:-6]
    return f"pulih_{filename}"


def render_sidebar() -> None:
    """Render sidebar with project metadata, method specs, and live demo guide."""
    with st.sidebar:
        st.markdown("## VaultXOR — CAPSTONE 2026")
        st.caption("Skema *Project Based Expo* — Cabang Kriptografi dan Keamanan Data")
        st.divider()
        st.markdown(
            """
            **Kombinasi 2 Metode Wajib:**
            1. **Kriptografi:** `Fernet` (`AES-128-CBC` + *PKCS7* + `HMAC-SHA256`, *Encrypt-then-MAC*)
            2. **Secret Sharing:** `XOR Secret Sharing` skema **$n$-dari-$n$** (default $n=3$, kunci master 32 byte)
            """
        )
        st.divider()
        st.markdown(
            """
            **Alur Demo Cepat:**
            1. **Amankan Berkas:** Unggah file $\\rightarrow$ enkripsi ke `.vault` & unduh 3 `.key`.
            2. **Uji Keamanan ($n-1$):** Coba buka `.vault` hanya dengan 2 share $\\rightarrow$ ditolak `InvalidToken`.
            3. **Uji Anti-Tamper:** Centang modifikasi 1 bit `.vault` $\\rightarrow$ ditolak verifikasi HMAC.
            4. **Pemulihan Utuh:** Masukkan 3 share valid $\\rightarrow$ `Hash Match = True`, `BER = 0.0%`.
            5. **Benchmark:** Jalankan uji otomatis 10 payload (`1 KB`–`50 MB`).
            """
        )
        st.divider()
        st.caption("Ketua Tim: Muhammad Al Bukhari (NIM. 240535610175) • DTEI FT UM")


def render_encrypt_tab() -> None:
    """Render Feature 1: Amankan Berkas (Encrypt & Split)."""
    st.subheader("1. Amankan Berkas (Encrypt & Split)")
    st.write(
        "Unggah berkas dokumen maupun biner sembarang untuk dienkripsi dengan **Fernet** "
        "menjadi berkas `.vault`, lalu kunci masternya (32 byte) dipecah menjadi $n$ share "
        "independen menggunakan operasi bitwise **XOR**."
    )

    col_up, col_cfg = st.columns([3, 1])
    with col_up:
        uploaded = st.file_uploader(
            "Pilih berkas yang akan diamankan",
            key="enc_uploader",
            help="Mendukung format sembarang: .txt, .pdf, .docx, .zip, .sql, .bin, .png, dll.",
        )
    with col_cfg:
        n_shares = int(
            st.number_input(
                "Jumlah Share (n)",
                min_value=2,
                max_value=6,
                value=3,
                step=1,
                help="Skema n-dari-n: seluruh n share wajib hadir untuk dekripsi.",
            )
        )

    if uploaded is not None:
        raw_data = uploaded.getvalue()
        st.caption(f"Berkas terpilih: **`{uploaded.name}`** ({format_size(len(raw_data))} / {len(raw_data):,} byte)")

        if st.button("Amankan Berkas & Pecah Kunci", type="primary", use_container_width=True):
            if len(raw_data) == 0:
                st.warning("Berkas kosong (0 byte). Silakan unggah berkas berisi data untuk didemokan.")
            else:
                with st.spinner("Mengenkripsi berkas dengan Fernet dan memecah kunci master via XOR..."):
                    res = encrypt_and_split(raw_data, n=n_shares)
                    vault_sha = sha256_hex(res.vault_bytes)
                    ct_ent = compute_ciphertext_entropy(res.vault_bytes)
                    sh_ents = compute_share_bit_entropies(res.shares)
                    mean_corr, _ = compute_share_correlations(res.shares)

                st.session_state["last_enc"] = {
                    "original_filename": uploaded.name,
                    "vault_filename": f"{uploaded.name}.vault",
                    "original_bytes": raw_data,
                    "vault_bytes": res.vault_bytes,
                    "vault_sha256": vault_sha,
                    "original_sha256": res.original_sha256,
                    "shares": res.shares,
                    "n_shares": n_shares,
                    "original_size": res.original_size,
                    "vault_size": res.vault_size,
                    "expansion_pct": res.expansion_pct,
                    "enc_ms": res.enc_ms,
                    "split_ms": res.split_ms,
                    "ct_entropy": ct_ent,
                    "share_entropies": sh_ents,
                    "mean_corr": mean_corr,
                }

    enc_state = st.session_state.get("last_enc")
    if enc_state is not None:
        st.success(
            f"Berkas **`{enc_state['original_filename']}`** berhasil diamankan menjadi "
            f"**`{enc_state['vault_filename']}`** dengan **{enc_state['n_shares']} share kunci**."
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Ukuran Asli", format_size(enc_state["original_size"]), f"{enc_state['original_size']:,} B")
        m2.metric("Ukuran .vault", format_size(enc_state["vault_size"]), f"{enc_state['vault_size']:,} B")
        m3.metric("Ekspansi Ukuran", f"{enc_state['expansion_pct']:.2f}%", "Overhead Fernet + Base64")
        m4.metric(
            "Waktu Proses",
            f"{enc_state['enc_ms'] + enc_state['split_ms']:.2f} ms",
            f"Enc {enc_state['enc_ms']:.2f} ms | Split {enc_state['split_ms']:.3f} ms",
        )

        st.markdown("**Hash SHA-256 Berkas Asli (Acuan Verifikasi Integritas):**")
        st.code(enc_state["original_sha256"], language="text")

        # Perbandingan sebelum vs sesudah
        st.markdown("**Perbandingan Isi Sebelum vs Sesudah Pengamanan:**")
        c_before, c_after = st.columns(2)
        with c_before:
            lbl, snippet = preview_content(enc_state["original_bytes"])
            st.caption(f"Sebelum ({lbl})")
            st.code(snippet, language="text")
        with c_after:
            token_preview = enc_state["vault_bytes"][:360].decode("ascii", errors="replace")
            if len(enc_state["vault_bytes"]) > 360:
                token_preview += "\n..."
            st.caption(
                f"Sesudah — Token Fernet `.vault` (Entropi: {enc_state['ct_entropy']:.4f} bit/byte)"
            )
            st.code(token_preview, language="text")

        st.download_button(
            label=f"Unduh Berkas Terenkripsi ({enc_state['vault_filename']})",
            data=enc_state["vault_bytes"],
            file_name=enc_state["vault_filename"],
            mime="application/octet-stream",
            type="primary",
            use_container_width=True,
        )

        st.markdown(
            f"**Distribusi {enc_state['n_shares']} Share Kunci (Masing-masing 32 Byte | "
            f"Rata-rata Korelasi Antar Share: `{enc_state['mean_corr']:.4f}`):**"
        )
        share_cols = st.columns(enc_state["n_shares"])
        for idx, (col, share_bytes, s_ent) in enumerate(
            zip(share_cols, enc_state["shares"], enc_state["share_entropies"]),
            start=1,
        ):
            with col:
                st.markdown(f"**Share {idx}** (`entropi bit: {s_ent:.4f}`)")
                st.code(share_bytes.hex(), language="text")
                st.download_button(
                    label=f"Unduh share_{idx}.key",
                    data=share_bytes,
                    file_name=f"share_{idx}.key",
                    mime="application/octet-stream",
                    key=f"dl_share_{idx}",
                    use_container_width=True,
                )


def _load_shares_for_decryption(enc_state: dict | None, use_session_vault: bool) -> tuple[list[bytes], list[str]]:
    """Collect share bytes from session demo presets, uploaded .key files, or pasted hex inputs."""
    errors: list[str] = []
    shares: list[bytes] = []

    if use_session_vault and enc_state is not None:
        source_mode = st.radio(
            "Sumber Share Kunci",
            options=[
                "Sesi Demo Cepat (Pilih Sebagian / Semua Share)",
                "Unggah Berkas .key Manual",
                "Tempel Teks Hex Manual",
            ],
            horizontal=True,
            key="dec_share_mode_session",
        )
    else:
        source_mode = st.radio(
            "Sumber Share Kunci",
            options=["Unggah Berkas .key Manual", "Tempel Teks Hex Manual"],
            horizontal=True,
            key="dec_share_mode_manual",
        )

    if source_mode == "Sesi Demo Cepat (Pilih Sebagian / Semua Share)" and enc_state is not None:
        total_n = enc_state["n_shares"]
        selected_indices = st.multiselect(
            "Pilih share yang ikut dimasukkan (hapus 1 share untuk simulasi uji n-1!)",
            options=list(range(1, total_n + 1)),
            default=list(range(1, total_n + 1)),
            format_func=lambda i: f"Share {i} (share_{i}.key)",
        )
        for i in selected_indices:
            shares.append(enc_state["shares"][i - 1])
        if len(selected_indices) < total_n:
            st.info(
                f"Mode uji keamanan aktif: hanya **{len(selected_indices)} dari {total_n}** share dipilih "
                "(seharusnya diblokir oleh verifikasi HMAC `InvalidToken`)."
            )

    elif source_mode == "Unggah Berkas .key Manual":
        uploaded_keys = st.file_uploader(
            "Unggah berkas share (.key)",
            accept_multiple_files=True,
            key="dec_key_files",
            help="Unggah 3 file share untuk dekripsi normal, atau hanya 2 file untuk simulasi uji n-1.",
        )
        for kf in uploaded_keys:
            try:
                shares.append(parse_share_input(raw_bytes=kf.getvalue()))
            except ValueError as exc:
                errors.append(f"`{kf.name}`: {exc}")

    else:
        m_count = int(
            st.number_input(
                "Jumlah share hex yang akan dimasukkan",
                min_value=1,
                max_value=6,
                value=3,
                step=1,
                key="dec_hex_count",
            )
        )
        for idx in range(1, m_count + 1):
            hex_val = st.text_input(
                f"Hex Share {idx} (64 karakter hex)",
                key=f"dec_hex_input_{idx}",
                placeholder="Tempel 64 karakter hex share...",
            )
            if hex_val.strip():
                try:
                    shares.append(parse_share_input(hex_text=hex_val))
                except ValueError as exc:
                    errors.append(f"Share {idx}: {exc}")

    return shares, errors


def render_decrypt_tab() -> None:
    """Render Feature 2: Pulihkan Berkas & Simulasi Uji Keamanan (Combine & Decrypt)."""
    st.subheader("2. Pulihkan Berkas & Simulasi Uji Keamanan (Combine & Decrypt)")
    st.write(
        "Unggah berkas `.vault` dan gabungkan share kunci untuk memulihkan berkas asli. "
        "Anda juga dapat menguji skenario serangan **$n-1$ share** maupun **modifikasi 1 bit pada `.vault`** "
        "untuk membuktikan mekanisme *Verify-before-Decrypt*."
    )

    enc_state = st.session_state.get("last_enc")
    use_session_vault = False
    if enc_state is not None:
        use_session_vault = st.checkbox(
            f"Gunakan berkas .vault dari hasil Enkripsi terakhir ({enc_state['vault_filename']})",
            value=True,
            key="use_session_vault",
        )

    vault_bytes: bytes | None = None
    vault_filename = "berkas_pulih"
    if use_session_vault and enc_state is not None:
        vault_bytes = enc_state["vault_bytes"]
        vault_filename = enc_state["vault_filename"]
    else:
        uploaded_vault = st.file_uploader(
            "Unggah berkas terenkripsi (.vault)",
            key="dec_vault_uploader",
        )
        if uploaded_vault is not None:
            vault_bytes = uploaded_vault.getvalue()
            vault_filename = uploaded_vault.name

    shares, parse_errors = _load_shares_for_decryption(enc_state, use_session_vault)

    with st.expander("Opsi Uji Integritas & Verifikasi Silang (SHA-256 / BER)", expanded=True):
        simulate_tamper = st.checkbox(
            "Simulasikan modifikasi 1 bit pada berkas .vault (Uji Anti-Tampering HMAC)",
            value=False,
            help="Membalik 1 bit di tengah berkas .vault sebelum dekripsi untuk membuktikan HMAC-SHA256 menolak berkas rusak.",
        )

        auto_ref_bytes: bytes | None = None
        auto_ref_sha: str = ""
        if vault_bytes is not None and enc_state is not None and sha256_hex(vault_bytes) == enc_state["vault_sha256"]:
            auto_ref_bytes = enc_state["original_bytes"]
            auto_ref_sha = enc_state["original_sha256"]

        col_ref1, col_ref2 = st.columns(2)
        with col_ref1:
            expected_sha = st.text_input(
                "SHA-256 Referensi Asli (Opsional)",
                value=auto_ref_sha,
                help="Otomatis terisi jika menggunakan berkas dari sesi Amankan Berkas terakhir.",
            ).strip().lower()
        with col_ref2:
            ref_file = st.file_uploader(
                "Atau unggah berkas asli pembanding untuk hitung BER (Opsional)",
                key="dec_ref_uploader",
            )
            if ref_file is not None:
                auto_ref_bytes = ref_file.getvalue()
                if not expected_sha:
                    expected_sha = sha256_hex(auto_ref_bytes)

    if st.button("Gabungkan Share & Dekripsi Berkas", type="primary", use_container_width=True):
        if vault_bytes is None or len(vault_bytes) == 0:
            st.warning("Silakan pilih atau unggah berkas `.vault` terlebih dahulu.")
            return
        if parse_errors:
            for err in parse_errors:
                st.error(err)
            return
        if not shares:
            st.warning("Belum ada share kunci yang dimasukkan.")
            return

        target_vault = tamper_vault_byte(vault_bytes) if simulate_tamper else vault_bytes

        try:
            dec_res = combine_and_decrypt(target_vault, shares)
        except InvalidToken:
            st.error(
                "AKSES DITOLAK — Verifikasi Integritas HMAC Gagal (`InvalidToken`)!\n\n"
                "Kemungkinan penyebab:\n"
                "- Jumlah share tidak lengkap (uji $n-1$ share), atau ada share yang salah/rusak.\n"
                "- Berkas `.vault` telah dimodifikasi (walau hanya 1 bit).\n\n"
                "Karena **Fernet** menerapkan *Verify-before-Decrypt*, sistem menolak dekripsi dan **tidak membocorkan 1 byte pun data**."
            )
            return
        except ValueError as exc:
            st.error(f"Gagal memproses share kunci: {exc}")
            return

        st.success(
            "PEMULIHAN BERHASIL — Seluruh share valid dan segel integritas HMAC-SHA256 terverifikasi."
        )

        hash_match_text = "Tidak diverifikasi (referensi belum diisi)"
        ber_text = "N/A"
        if expected_sha:
            is_match = dec_res.recovered_sha256 == expected_sha
            hash_match_text = "True (100% Identik)" if is_match else "False (Berbeda!)"
        if auto_ref_bytes is not None:
            ber_val = compute_ber_percent(auto_ref_bytes, dec_res.recovered_bytes)
            ber_text = f"{ber_val:.1f}%"

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("SHA-256 Hash Match", hash_match_text)
        m2.metric("Bit Error Rate (BER)", ber_text)
        m3.metric("Waktu XOR Combine", f"{dec_res.comb_ms:.4f} ms")
        m4.metric("Waktu Fernet Decrypt", f"{dec_res.dec_ms:.3f} ms")

        st.markdown("**Hash SHA-256 Berkas Hasil Pemulihan:**")
        st.code(dec_res.recovered_sha256, language="text")

        lbl, snippet = preview_content(dec_res.recovered_bytes)
        st.caption(f"Hasil Pemulihan ({lbl})")
        st.code(snippet, language="text")

        recovered_name = strip_vault_suffix(vault_filename)
        st.download_button(
            label=f"Unduh Berkas Hasil Pemulihan ({recovered_name})",
            data=dec_res.recovered_bytes,
            file_name=recovered_name,
            mime="application/octet-stream",
            type="primary",
            use_container_width=True,
        )


def _display_benchmark_results(df: pd.DataFrame) -> None:
    """Display KPI cards, data table, CSV export, and 4 Matplotlib evaluation charts."""
    total_payloads = len(df)
    hash_ok = int(df["Hash Match"].sum())
    blocked_ok = int(df["n-1 Blocked"].sum())
    max_ber = float(df["BER (%)"].max())
    ct_min = float(df["Entropi Ciphertext (bit/byte)"].min())
    ct_max = float(df["Entropi Ciphertext (bit/byte)"].max())
    xor_max_ms = float(max(df["Split (ms)"].max(), df["Comb (ms)"].max()))

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Hash Match", f"{hash_ok}/{total_payloads}", "100% Identik" if hash_ok == total_payloads else "Ada Gagal")
    k2.metric("BER Maksimum", f"{max_ber:.1f}%", "Zero Error" if max_ber == 0.0 else "Ada Error")
    k3.metric("Uji n-1 Blocked", f"{blocked_ok}/{total_payloads}", "InvalidToken" if blocked_ok == total_payloads else "Cek")
    k4.metric("Entropi Ciphertext", f"{ct_min:.4f}–{ct_max:.4f}", "bit/byte (ideal 8.0)")
    k5.metric("Maks XOR Split/Comb", f"{xor_max_ms:.4f} ms", "Konstan < 1 ms")

    st.markdown("**Tabel Hasil Evaluasi:**")
    st.dataframe(df, use_container_width=True, hide_index=True)

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Ekspor Tabel Hasil Benchmark (.csv)",
        data=csv_bytes,
        file_name="benchmark_fernet_xor_10_payload.csv",
        mime="text/csv",
        use_container_width=True,
    )

    figs = build_benchmark_figures(df)
    st.markdown("**Visualisasi Grafik Evaluasi:**")
    c1, c2 = st.columns(2)
    with c1:
        st.pyplot(figs["timing"], use_container_width=True)
        st.pyplot(figs["correlation"], use_container_width=True)
    with c2:
        st.pyplot(figs["entropy"], use_container_width=True)
        st.pyplot(figs["expansion"], use_container_width=True)

    for fig in figs.values():
        plt.close(fig)


def render_benchmark_tab() -> None:
    """Render Feature 3: Panel Evaluasi & Benchmark Otomatis 10 Payload."""
    st.subheader("3. Panel Evaluasi & Benchmark Otomatis 10 Payload")
    st.write(
        "Menjalankan pengujian terukur pada **10 ukuran payload berbeda** "
        "(`1 KB`, `10 KB`, `100 KB`, `500 KB`, `1 MB`, `5 MB`, `10 MB`, `20 MB`, `35 MB`, `50 MB`) "
        "untuk mengevaluasi integritas, keamanan $n-1$, keacakan (entropi & korelasi), ekspansi ukuran, dan waktu proses."
    )

    col_opt, col_btn = st.columns([2, 2])
    with col_opt:
        quick_mode = st.checkbox(
            "Mode Demo Kilat (hanya 6 payload: 1 KB – 5 MB)",
            value=False,
            help="Biarkan tidak dicentang untuk menjalankan penuh 10 payload (1 KB – 50 MB).",
        )
    with col_btn:
        run_clicked = st.button(
            "Jalankan Benchmark Otomatis",
            type="primary",
            use_container_width=True,
        )

    if run_clicked:
        specs = PAYLOAD_SPECS[:6] if quick_mode else PAYLOAD_SPECS
        progress_bar = st.progress(0.0, text="Mempersiapkan pengujian payload...")

        def on_progress(done: int, total: int, message: str) -> None:
            progress_bar.progress(done / total, text=message)

        df_result = run_full_benchmark(n=3, payload_specs=specs, progress_callback=on_progress)
        st.session_state["benchmark_df"] = df_result
        st.session_state["benchmark_source"] = "live"

    if "benchmark_df" not in st.session_state and CACHED_BENCHMARK_CSV.exists():
        st.session_state["benchmark_df"] = pd.read_csv(CACHED_BENCHMARK_CSV)
        st.session_state["benchmark_source"] = "cached"

    if "benchmark_df" in st.session_state:
        src = st.session_state.get("benchmark_source", "live")
        if src == "cached":
            st.info(
                "Menampilkan hasil benchmark tersimpan (`outputs/benchmark_10_payload.csv`). "
                "Klik **Jalankan Benchmark Otomatis** di atas untuk menjalankan ulang pengujian secara langsung."
            )
        _display_benchmark_results(st.session_state["benchmark_df"])


def main() -> None:
    """Entry point for the CAPSTONE 2026 Streamlit application."""
    st.set_page_config(
        page_title="VaultXOR — Pengamanan Berkas Fernet + XOR Secret Sharing",
        page_icon="🔐",
        layout="wide",
    )

    render_sidebar()

    st.title("🔐 VaultXOR — Pengamanan Berkas Terdistribusi")
    st.caption(
        "Fernet Authenticated Encryption (AES-128-CBC + HMAC-SHA256) + "
        "XOR Secret Sharing (n-dari-n, n=3) • CAPSTONE 2026"
    )

    tab1, tab2, tab3 = st.tabs(
        [
            "1. Amankan Berkas (Encrypt & Split)",
            "2. Pulihkan Berkas & Uji Keamanan",
            "3. Panel Evaluasi 10 Payload",
        ]
    )

    with tab1:
        render_encrypt_tab()
    with tab2:
        render_decrypt_tab()
    with tab3:
        render_benchmark_tab()


if __name__ == "__main__":
    main()
