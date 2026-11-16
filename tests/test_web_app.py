"""End-to-end HTTP integration tests for the Starlette HTML/API server (web_app.py)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import pytest


ROOT_DIR = Path(__file__).resolve().parent.parent


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _encode_multipart(
    fields: list[tuple[str, str]],
    files: list[tuple[str, str, bytes]],
) -> tuple[bytes, str]:
    boundary = f"----VaultXORBoundary{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, val in fields:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{val}\r\n"
            ).encode("utf-8")
        )
    for field_name, filename, content in files:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode("utf-8")
        )
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


@pytest.fixture(scope="module")
def live_server_url() -> str:
    port = _find_free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "web_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(ROOT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(30):
            time.sleep(0.25)
            try:
                with urllib.request.urlopen(f"{base_url}/api/benchmark/cached", timeout=2) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                continue
        else:
            raise RuntimeError("Uvicorn test server failed to start in time.")
        yield base_url
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_html_and_static_assets_served(live_server_url: str) -> None:
    with urllib.request.urlopen(f"{live_server_url}/", timeout=5) as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "VaultXOR" in html
        assert "/static/app.js" in html

    for asset in ("/static/styles.css", "/static/app.js"):
        with urllib.request.urlopen(f"{live_server_url}{asset}", timeout=5) as resp:
            assert resp.status == 200
            assert len(resp.read()) > 100


def test_encrypt_download_decrypt_tamper_and_n_minus_one_e2e(live_server_url: str) -> None:
    # Use a >1 MB payload to verify MAX_UPLOAD_PART_BYTES exceeds Starlette's 1 MB default.
    original_bytes = os.urandom(1_500_000)

    body, ctype = _encode_multipart(
        fields=[("n_shares", "3")],
        files=[("file", "payload_besar.bin", original_bytes)],
    )
    req = urllib.request.Request(
        f"{live_server_url}/api/encrypt",
        data=body,
        headers={"Content-Type": ctype},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        assert resp.status == 200
        enc_data = json.loads(resp.read().decode("utf-8"))

    assert enc_data["vault_filename"] == "payload_besar.bin.vault"
    assert enc_data["n_shares"] == 3
    assert len(enc_data["shares"]) == 3
    assert enc_data["vault_preview"].startswith("gAAAAAB")

    # Download real .vault and 3 .key files via HTTP endpoints
    with urllib.request.urlopen(f"{live_server_url}{enc_data['vault_download_url']}", timeout=10) as r:
        vault_bytes = r.read()
    assert vault_bytes.startswith(b"gAAAAAB")

    share_bytes_list: list[bytes] = []
    for share in enc_data["shares"]:
        with urllib.request.urlopen(f"{live_server_url}{share['download_url']}", timeout=5) as r:
            sb = r.read()
            assert len(sb) == 32
            share_bytes_list.append(sb)

    # 1) Decrypt with all 3 uploaded .key files -> success, Hash Match True, BER 0.0%
    dec_body, dec_ctype = _encode_multipart(
        fields=[
            ("expected_sha256", enc_data["original_sha256"]),
            ("simulate_tamper", "false"),
        ],
        files=[
            ("vault_file", enc_data["vault_filename"], vault_bytes),
            ("ref_file", "payload_besar.bin", original_bytes),
            ("share_files", "share_1.key", share_bytes_list[0]),
            ("share_files", "share_2.key", share_bytes_list[1]),
            ("share_files", "share_3.key", share_bytes_list[2]),
        ],
    )
    dec_req = urllib.request.Request(
        f"{live_server_url}/api/decrypt",
        data=dec_body,
        headers={"Content-Type": dec_ctype},
        method="POST",
    )
    with urllib.request.urlopen(dec_req, timeout=15) as resp:
        dec_data = json.loads(resp.read().decode("utf-8"))

    assert dec_data["status"] == "ok"
    assert dec_data["recovered_filename"] == "payload_besar.bin"
    assert dec_data["hash_match"] is True
    assert dec_data["ber_pct"] == 0.0

    with urllib.request.urlopen(f"{live_server_url}{dec_data['download_url']}", timeout=10) as r:
        assert r.read() == original_bytes

    # 2) n-1 attack (only 2 of 3 shares) -> rejected with InvalidToken
    n1_body, n1_ctype = _encode_multipart(
        fields=[("simulate_tamper", "false")],
        files=[
            ("vault_file", enc_data["vault_filename"], vault_bytes),
            ("share_files", "share_1.key", share_bytes_list[0]),
            ("share_files", "share_2.key", share_bytes_list[1]),
        ],
    )
    n1_req = urllib.request.Request(
        f"{live_server_url}/api/decrypt",
        data=n1_body,
        headers={"Content-Type": n1_ctype},
        method="POST",
    )
    with urllib.request.urlopen(n1_req, timeout=10) as resp:
        n1_data = json.loads(resp.read().decode("utf-8"))
    assert n1_data["status"] == "rejected"
    assert n1_data["error_type"] == "InvalidToken"

    # 3) 1-bit tamper with all 3 valid shares -> rejected with InvalidToken
    tamper_body, tamper_ctype = _encode_multipart(
        fields=[
            ("simulate_tamper", "true"),
            ("share_hexes", json.dumps([s["hex"] for s in enc_data["shares"]])),
        ],
        files=[("vault_file", enc_data["vault_filename"], vault_bytes)],
    )
    tamper_req = urllib.request.Request(
        f"{live_server_url}/api/decrypt",
        data=tamper_body,
        headers={"Content-Type": tamper_ctype},
        method="POST",
    )
    with urllib.request.urlopen(tamper_req, timeout=10) as resp:
        tamper_data = json.loads(resp.read().decode("utf-8"))
    assert tamper_data["status"] == "rejected"
    assert tamper_data["error_type"] == "InvalidToken"


def test_benchmark_cached_and_csv_endpoints(live_server_url: str) -> None:
    with urllib.request.urlopen(f"{live_server_url}/api/benchmark/cached", timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    assert data["available"] is True
    assert len(data["rows"]) == 10
    assert data["summary"]["hash_ok"] == 10
    assert data["summary"]["blocked_ok"] == 10

    with urllib.request.urlopen(f"{live_server_url}/api/benchmark/csv", timeout=5) as resp:
        assert resp.status == 200
        csv_text = resp.read().decode("utf-8")
        assert "1 KB" in csv_text and "50 MB" in csv_text


def test_benchmark_stream_quick_sse(live_server_url: str) -> None:
    events: list[dict] = []
    try:
        with urllib.request.urlopen(f"{live_server_url}/api/benchmark/stream?mode=quick", timeout=30) as resp:
            assert resp.status == 200
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if line.startswith("data: "):
                    events.append(json.loads(line[6:]))
        assert any(ev.get("type") == "progress" for ev in events)
        done_events = [ev for ev in events if ev.get("type") == "done"]
        assert len(done_events) == 1
        assert len(done_events[0]["rows"]) == 6
        assert done_events[0]["summary"]["hash_ok"] == 6
    finally:
        out_dir = ROOT_DIR / "outputs"
        for name in (
            "benchmark_quick_payload.csv",
            "chart_quick_timing.png",
            "chart_quick_entropy.png",
            "chart_quick_correlation.png",
            "chart_quick_expansion.png",
        ):
            (out_dir / name).unlink(missing_ok=True)

