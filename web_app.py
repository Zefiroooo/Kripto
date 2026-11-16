"""Starlette web server providing an HTML/CSS/JS frontend for VaultXOR (CAPSTONE 2026)."""

from __future__ import annotations

import json
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any

import anyio
import matplotlib.pyplot as plt
import pandas as pd
import uvicorn
from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

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
    run_single_payload_benchmark,
)


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
OUTPUTS_DIR = BASE_DIR / "outputs"
CACHED_BENCHMARK_CSV = OUTPUTS_DIR / "benchmark_10_payload.csv"
MAX_STORED_JOBS = 4
MAX_UPLOAD_PART_BYTES = 100 * 1024 * 1024


class JobStore:
    """Bounded in-memory store for recent encryption & recovery demo artifacts."""

    def __init__(self, max_items: int = MAX_STORED_JOBS) -> None:
        self._max_items = max_items
        self._items: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def put(self, record: dict[str, Any]) -> str:
        item_id = uuid.uuid4().hex[:12]
        self._items[item_id] = record
        self._items.move_to_end(item_id)
        while len(self._items) > self._max_items:
            self._items.popitem(last=False)
        return item_id

    def get(self, item_id: str) -> dict[str, Any] | None:
        return self._items.get(item_id)


ENC_STORE = JobStore()
REC_STORE = JobStore()


def _safe_filename(name: str, fallback: str = "berkas") -> str:
    clean = Path(name).name.replace('"', "").replace("\r", "").replace("\n", "").strip()
    return clean or fallback


def _strip_vault_suffix(filename: str) -> str:
    clean = _safe_filename(filename, "berkas.vault")
    if clean.lower().endswith(".vault") and len(clean) > 6:
        return clean[:-6]
    return f"pulih_{clean}"


def _build_preview(data: bytes, max_chars: int = 400) -> dict[str, str]:
    sample = data[:4096]
    try:
        text = sample.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text[:120]):
            snippet = text[:max_chars]
            if len(data) > max_chars:
                snippet += "\n..."
            return {"kind": "Pratinjau Teks (UTF-8)", "text": snippet}
    except UnicodeDecodeError:
        pass

    hex_str = " ".join(f"{b:02X}" for b in data[:64])
    if len(data) > 64:
        hex_str += " ..."
    return {"kind": "Pratinjau Biner (64 Byte Awal dalam Hex)", "text": hex_str}


def _summarize_benchmark(df: pd.DataFrame) -> dict[str, Any]:
    total = int(len(df))
    return {
        "total_payloads": total,
        "hash_ok": int(df["Hash Match"].astype(bool).sum()),
        "blocked_ok": int(df["n-1 Blocked"].astype(bool).sum()),
        "max_ber": round(float(df["BER (%)"].max()), 6),
        "ct_entropy_min": round(float(df["Entropi Ciphertext (bit/byte)"].min()), 4),
        "ct_entropy_max": round(float(df["Entropi Ciphertext (bit/byte)"].max()), 4),
        "xor_max_ms": round(float(max(df["Split (ms)"].max(), df["Comb (ms)"].max())), 4),
        "max_total_ms": round(float(df["Total (ms)"].max()), 3),
    }


def _df_to_json_rows(df: pd.DataFrame) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_row in df.to_dict(orient="records"):
        clean_row: dict[str, Any] = {}
        for k, v in raw_row.items():
            if hasattr(v, "item"):
                v = v.item()
            clean_row[str(k)] = v
        records.append(clean_row)
    return records


def _save_benchmark_outputs(df: pd.DataFrame, is_full: bool = True) -> dict[str, str]:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    if is_full:
        df.to_csv(CACHED_BENCHMARK_CSV, index=False)
        prefix = "chart_"
    else:
        df.to_csv(OUTPUTS_DIR / "benchmark_quick_payload.csv", index=False)
        prefix = "chart_quick_"

    figs = build_benchmark_figures(df)
    chart_urls: dict[str, str] = {}
    for name, fig in figs.items():
        filename = f"{prefix}{name}.png"
        fig.savefig(OUTPUTS_DIR / filename, dpi=200, bbox_inches="tight")
        plt.close(fig)
        chart_urls[name] = f"/outputs/{filename}"
    return chart_urls


async def index_page(_request: Request) -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


async def api_encrypt(request: Request) -> JSONResponse:
    form = await request.form(max_part_size=MAX_UPLOAD_PART_BYTES)
    uploaded = form.get("file")
    if not isinstance(uploaded, UploadFile):
        return JSONResponse({"error": "Silakan pilih berkas yang akan diamankan."}, status_code=400)

    raw_data = await uploaded.read()
    if len(raw_data) == 0:
        return JSONResponse({"error": "Berkas kosong (0 byte) tidak dapat dienkripsi."}, status_code=400)

    try:
        n_shares = int(form.get("n_shares", 3))
    except (TypeError, ValueError):
        return JSONResponse({"error": "Nilai jumlah share harus berupa bilangan bulat."}, status_code=400)
    if not (2 <= n_shares <= 6):
        return JSONResponse({"error": "Jumlah share (n) harus berada di antara 2 sampai 6."}, status_code=400)

    original_filename = _safe_filename(uploaded.filename or "berkas.bin")
    vault_filename = f"{original_filename}.vault"

    def _run() -> dict[str, Any]:
        res = encrypt_and_split(raw_data, n=n_shares)
        ct_entropy = compute_ciphertext_entropy(res.vault_bytes)
        share_entropies = compute_share_bit_entropies(res.shares)
        mean_corr, pair_corrs = compute_share_correlations(res.shares)
        return {
            "res": res,
            "ct_entropy": ct_entropy,
            "share_entropies": share_entropies,
            "mean_corr": mean_corr,
            "pair_corrs": pair_corrs,
        }

    computed = await anyio.to_thread.run_sync(_run)
    res = computed["res"]

    job_id = ENC_STORE.put(
        {
            "original_filename": original_filename,
            "vault_filename": vault_filename,
            "original_bytes": raw_data,
            "original_sha256": res.original_sha256,
            "vault_bytes": res.vault_bytes,
            "vault_sha256": sha256_hex(res.vault_bytes),
            "shares": res.shares,
            "n_shares": n_shares,
        }
    )

    token_snippet = res.vault_bytes[:360].decode("ascii", errors="replace")
    if len(res.vault_bytes) > 360:
        token_snippet += "\n..."

    shares_payload = [
        {
            "index": idx,
            "filename": f"share_{idx}.key",
            "hex": share.hex(),
            "size_bytes": len(share),
            "bit_entropy": round(computed["share_entropies"][idx - 1], 4),
            "download_url": f"/api/artifact/{job_id}/share/{idx}",
        }
        for idx, share in enumerate(res.shares, start=1)
    ]

    return JSONResponse(
        {
            "job_id": job_id,
            "original_filename": original_filename,
            "vault_filename": vault_filename,
            "original_size": res.original_size,
            "vault_size": res.vault_size,
            "expansion_pct": round(res.expansion_pct, 2),
            "enc_ms": round(res.enc_ms, 3),
            "split_ms": round(res.split_ms, 4),
            "original_sha256": res.original_sha256,
            "ct_entropy": round(computed["ct_entropy"], 4),
            "mean_corr": round(computed["mean_corr"], 4),
            "pair_corrs": [
                {"pair": name, "r": round(val, 4)} for name, val in computed["pair_corrs"]
            ],
            "original_preview": _build_preview(raw_data),
            "vault_preview": token_snippet,
            "vault_download_url": f"/api/artifact/{job_id}/vault",
            "n_shares": n_shares,
            "shares": shares_payload,
        }
    )


async def api_download_artifact(request: Request) -> Response:
    job_id = request.path_params["job_id"]
    kind = request.path_params["kind"]
    job = ENC_STORE.get(job_id)
    if job is None:
        return JSONResponse({"error": "Sesi artefak tidak ditemukan atau sudah kedaluwarsa."}, status_code=404)

    if kind == "vault":
        filename = job["vault_filename"]
        return Response(
            content=job["vault_bytes"],
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if kind == "share":
        try:
            idx = int(request.path_params["idx"])
        except (KeyError, ValueError):
            return JSONResponse({"error": "Indeks share tidak valid."}, status_code=400)
        shares = job["shares"]
        if not (1 <= idx <= len(shares)):
            return JSONResponse({"error": "Indeks share di luar jangkauan."}, status_code=404)
        return Response(
            content=shares[idx - 1],
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="share_{idx}.key"'},
        )

    return JSONResponse({"error": "Jenis artefak tidak dikenali."}, status_code=400)


async def api_decrypt(request: Request) -> JSONResponse:
    form = await request.form(max_part_size=MAX_UPLOAD_PART_BYTES)
    use_job_id = str(form.get("use_job_id", "")).strip()
    simulate_tamper = str(form.get("simulate_tamper", "false")).lower() == "true"
    expected_sha = str(form.get("expected_sha256", "")).strip().lower()

    vault_bytes: bytes | None = None
    vault_filename = "berkas_pulih"
    auto_ref_bytes: bytes | None = None

    uploaded_vault = form.get("vault_file")
    session_job = ENC_STORE.get(use_job_id) if use_job_id else None

    if isinstance(uploaded_vault, UploadFile):
        vault_bytes = await uploaded_vault.read()
        vault_filename = _safe_filename(uploaded_vault.filename or "berkas.vault")
    elif session_job is not None:
        vault_bytes = session_job["vault_bytes"]
        vault_filename = session_job["vault_filename"]

    if vault_bytes is None or len(vault_bytes) == 0:
        return JSONResponse({"error": "Berkas .vault belum dipilih atau kosong."}, status_code=400)

    if session_job is not None and sha256_hex(vault_bytes) == session_job["vault_sha256"]:
        auto_ref_bytes = session_job["original_bytes"]
        if not expected_sha:
            expected_sha = session_job["original_sha256"]

    ref_file = form.get("ref_file")
    if isinstance(ref_file, UploadFile):
        ref_bytes = await ref_file.read()
        if len(ref_bytes) > 0:
            auto_ref_bytes = ref_bytes
            if not expected_sha:
                expected_sha = sha256_hex(ref_bytes)

    shares: list[bytes] = []

    # 1) Session share indices (optional quick demo mode)
    session_indices_raw = str(form.get("session_share_indices", "")).strip()
    if session_indices_raw and session_job is not None:
        try:
            indices = json.loads(session_indices_raw)
            for idx in indices:
                i = int(idx)
                if 1 <= i <= len(session_job["shares"]):
                    shares.append(session_job["shares"][i - 1])
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": f"Pilihan share sesi tidak valid: {exc}"}, status_code=400)

    # 2) Uploaded .key files
    for uploaded_key in form.getlist("share_files"):
        if isinstance(uploaded_key, UploadFile):
            key_data = await uploaded_key.read()
            if len(key_data) > 0:
                try:
                    shares.append(parse_share_input(raw_bytes=key_data))
                except ValueError as exc:
                    key_name = _safe_filename(uploaded_key.filename or "share.key")
                    return JSONResponse({"error": f"{key_name}: {exc}"}, status_code=400)

    # 3) Pasted hex shares JSON list
    hex_list_raw = str(form.get("share_hexes", "")).strip()
    if hex_list_raw:
        try:
            hex_items = json.loads(hex_list_raw)
        except ValueError:
            return JSONResponse({"error": "Format daftar hex share tidak valid."}, status_code=400)
        for pos, hex_str in enumerate(hex_items, start=1):
            if isinstance(hex_str, str) and hex_str.strip():
                try:
                    shares.append(parse_share_input(hex_text=hex_str))
                except ValueError as exc:
                    return JSONResponse({"error": f"Hex Share {pos}: {exc}"}, status_code=400)

    if not shares:
        return JSONResponse({"error": "Belum ada share kunci yang dimasukkan."}, status_code=400)

    target_vault = tamper_vault_byte(vault_bytes) if simulate_tamper else vault_bytes

    def _decrypt() -> dict[str, Any]:
        dec_res = combine_and_decrypt(target_vault, shares)
        ber_pct: float | None = None
        if auto_ref_bytes is not None:
            ber_pct = round(compute_ber_percent(auto_ref_bytes, dec_res.recovered_bytes), 6)
        return {"dec_res": dec_res, "ber_pct": ber_pct}

    try:
        out = await anyio.to_thread.run_sync(_decrypt)
    except InvalidToken:
        return JSONResponse(
            {
                "status": "rejected",
                "error_type": "InvalidToken",
                "message": (
                    "AKSES DITOLAK — Verifikasi Integritas HMAC Gagal (InvalidToken). "
                    "Jumlah share tidak lengkap (uji n-1), ada share salah, atau berkas .vault telah dimodifikasi. "
                    "Karena Fernet menerapkan Verify-before-Decrypt, sistem tidak membocorkan 1 byte pun data."
                ),
            },
            status_code=200,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    dec_res = out["dec_res"]
    recovered_name = _strip_vault_suffix(vault_filename)
    rec_id = REC_STORE.put(
        {
            "filename": recovered_name,
            "data": dec_res.recovered_bytes,
        }
    )

    hash_match: bool | None = None
    if expected_sha:
        hash_match = dec_res.recovered_sha256 == expected_sha

    return JSONResponse(
        {
            "status": "ok",
            "recovered_filename": recovered_name,
            "recovered_size": len(dec_res.recovered_bytes),
            "recovered_sha256": dec_res.recovered_sha256,
            "hash_match": hash_match,
            "ber_pct": out["ber_pct"],
            "comb_ms": round(dec_res.comb_ms, 4),
            "dec_ms": round(dec_res.dec_ms, 3),
            "preview": _build_preview(dec_res.recovered_bytes),
            "download_url": f"/api/recovered/{rec_id}",
        }
    )


async def api_download_recovered(request: Request) -> Response:
    rec_id = request.path_params["rec_id"]
    rec = REC_STORE.get(rec_id)
    if rec is None:
        return JSONResponse({"error": "Berkas hasil pemulihan tidak ditemukan."}, status_code=404)
    return Response(
        content=rec["data"],
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{rec["filename"]}"'},
    )


async def api_benchmark_cached(_request: Request) -> JSONResponse:
    if not CACHED_BENCHMARK_CSV.exists():
        return JSONResponse({"available": False})

    df = pd.read_csv(CACHED_BENCHMARK_CSV)
    return JSONResponse(
        {
            "available": True,
            "source": "cached",
            "rows": _df_to_json_rows(df),
            "summary": _summarize_benchmark(df),
            "csv_url": "/api/benchmark/csv",
            "chart_urls": {
                "timing": "/outputs/chart_timing.png",
                "entropy": "/outputs/chart_entropy.png",
                "correlation": "/outputs/chart_correlation.png",
                "expansion": "/outputs/chart_expansion.png",
            },
            "timestamp": int(CACHED_BENCHMARK_CSV.stat().st_mtime * 1000),
        }
    )


async def api_benchmark_stream(request: Request) -> StreamingResponse:
    mode = request.query_params.get("mode", "full")
    is_full = mode != "quick"
    specs = PAYLOAD_SPECS if is_full else PAYLOAD_SPECS[:6]

    async def event_stream():
        rows: list[dict[str, object]] = []
        total = len(specs)
        for idx, (label, size_bytes) in enumerate(specs, start=1):
            payload = {
                "type": "progress",
                "done": idx - 1,
                "total": total,
                "message": f"Menguji payload {label} ({idx}/{total})...",
            }
            yield f"data: {json.dumps(payload)}\n\n"
            row = await anyio.to_thread.run_sync(run_single_payload_benchmark, label, size_bytes, 3)
            rows.append(row)

        df = pd.DataFrame(rows)
        chart_urls = await anyio.to_thread.run_sync(_save_benchmark_outputs, df, is_full)
        done_payload = {
            "type": "done",
            "done": total,
            "total": total,
            "message": "Pengujian seluruh payload selesai.",
            "rows": _df_to_json_rows(df),
            "summary": _summarize_benchmark(df),
            "csv_url": "/api/benchmark/csv" if is_full else "/outputs/benchmark_quick_payload.csv",
            "chart_urls": chart_urls,
            "timestamp": int(time.time() * 1000),
        }
        yield f"data: {json.dumps(done_payload)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def api_benchmark_csv(_request: Request) -> Response:
    if not CACHED_BENCHMARK_CSV.exists():
        return JSONResponse({"error": "Data benchmark belum tersedia."}, status_code=404)
    return FileResponse(
        CACHED_BENCHMARK_CSV,
        media_type="text/csv",
        filename="benchmark_fernet_xor_10_payload.csv",
    )


async def json_http_exception(_request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)


def create_app() -> Starlette:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    routes = [
        Route("/", index_page, methods=["GET"]),
        Route("/api/encrypt", api_encrypt, methods=["POST"]),
        Route("/api/artifact/{job_id}/{kind}", api_download_artifact, methods=["GET"]),
        Route("/api/artifact/{job_id}/{kind}/{idx:int}", api_download_artifact, methods=["GET"]),
        Route("/api/decrypt", api_decrypt, methods=["POST"]),
        Route("/api/recovered/{rec_id}", api_download_recovered, methods=["GET"]),
        Route("/api/benchmark/cached", api_benchmark_cached, methods=["GET"]),
        Route("/api/benchmark/stream", api_benchmark_stream, methods=["GET"]),
        Route("/api/benchmark/csv", api_benchmark_csv, methods=["GET"]),
        Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
        Mount("/outputs", app=StaticFiles(directory=str(OUTPUTS_DIR)), name="outputs"),
    ]
    return Starlette(routes=routes, exception_handlers={HTTPException: json_http_exception})


app = create_app()


if __name__ == "__main__":
    uvicorn.run("web_app:app", host="127.0.0.1", port=8000, reload=False)
