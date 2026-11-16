(() => {
  "use strict";

  const state = {
    encFile: null,
    lastJob: null,
    decVaultFile: null,
    decKeyFiles: [],
    decShareMode: "files",
    benchSource: null,
  };

  function $(id) {
    return document.getElementById(id);
  }

  function formatBytes(numBytes) {
    if (numBytes < 1024) return `${numBytes} B`;
    if (numBytes < 1024 * 1024) return `${(numBytes / 1024).toFixed(2)} KB`;
    return `${(numBytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function showToast(msg) {
    const toast = $("toast");
    toast.textContent = msg;
    toast.classList.remove("hidden");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.add("hidden"), 2200);
  }

  function bindDropzone(zoneEl, inputEl, onFilesSelected) {
    zoneEl.addEventListener("click", () => inputEl.click());
    zoneEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        inputEl.click();
      }
    });
    zoneEl.addEventListener("dragover", (e) => {
      e.preventDefault();
      zoneEl.classList.add("dragover");
    });
    zoneEl.addEventListener("dragleave", () => {
      zoneEl.classList.remove("dragover");
    });
    zoneEl.addEventListener("drop", (e) => {
      e.preventDefault();
      zoneEl.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        onFilesSelected(Array.from(e.dataTransfer.files));
      }
    });
    inputEl.addEventListener("change", () => {
      if (inputEl.files && inputEl.files.length > 0) {
        onFilesSelected(Array.from(inputEl.files));
      }
    });
  }

  // --- Tabs ---
  function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      const isActive = btn.dataset.tab === tabName;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-selected", isActive ? "true" : "false");
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `tab-${tabName}`);
    });
  }

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // --- Copy buttons ---
  document.addEventListener("click", (e) => {
    const copyBtn = e.target.closest(".copy-btn");
    if (!copyBtn) return;
    const target = $(copyBtn.dataset.copyTarget);
    if (!target) return;
    navigator.clipboard.writeText(target.textContent.trim()).then(() => {
      showToast("Berhasil disalin ke clipboard");
    });
  });

  // --- Tab 1: Encrypt & Split ---
  bindDropzone($("enc-dropzone"), $("enc-file-input"), (files) => {
    state.encFile = files[0];
    $("enc-file-label").textContent = `${state.encFile.name} (${formatBytes(state.encFile.size)})`;
  });

  $("enc-submit-btn").addEventListener("click", async () => {
    const errEl = $("enc-error");
    errEl.classList.add("hidden");

    if (!state.encFile) {
      errEl.textContent = "Silakan pilih berkas yang akan diamankan terlebih dahulu.";
      errEl.classList.remove("hidden");
      return;
    }

    const btn = $("enc-submit-btn");
    btn.disabled = true;
    btn.textContent = "Memproses Enkripsi & Pembagian Kunci...";

    try {
      const formData = new FormData();
      formData.append("file", state.encFile);
      formData.append("n_shares", $("enc-n-shares").value);

      const resp = await fetch("/api/encrypt", { method: "POST", body: formData });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "Terjadi kesalahan saat mengenkripsi berkas.");
      }

      state.lastJob = data;
      renderEncryptResults(data);
      syncSessionToDecryptTab(data);
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    } finally {
      btn.disabled = false;
      btn.textContent = "Amankan Berkas & Pecah Kunci";
    }
  });

  function renderEncryptResults(data) {
    $("enc-results").classList.remove("hidden");
    $("enc-success-msg").textContent =
      `Berkas "${data.original_filename}" berhasil diamankan menjadi "${data.vault_filename}" dengan ${data.n_shares} share kunci.`;

    $("kpi-orig-size").textContent = formatBytes(data.original_size);
    $("kpi-orig-bytes").textContent = `${data.original_size.toLocaleString("id-ID")} byte`;
    $("kpi-vault-size").textContent = formatBytes(data.vault_size);
    $("kpi-vault-bytes").textContent = `${data.vault_size.toLocaleString("id-ID")} byte`;
    $("kpi-expansion").textContent = `${data.expansion_pct.toFixed(2)}%`;
    $("kpi-enc-time").textContent = `${(data.enc_ms + data.split_ms).toFixed(2)} ms`;
    $("kpi-enc-sub").textContent = `Enc ${data.enc_ms.toFixed(2)} ms | Split ${data.split_ms.toFixed(3)} ms`;

    $("enc-sha256").textContent = data.original_sha256;
    $("enc-orig-preview-kind").textContent = data.original_preview.kind;
    $("enc-orig-preview").textContent = data.original_preview.text;
    $("enc-ct-entropy-badge").textContent = `Entropi: ${data.ct_entropy.toFixed(4)} bit/byte`;
    $("enc-vault-preview").textContent = data.vault_preview;

    const dlVault = $("enc-download-vault");
    dlVault.href = data.vault_download_url;
    dlVault.download = data.vault_filename;
    dlVault.textContent = `Unduh Berkas Terenkripsi (${data.vault_filename})`;

    $("enc-corr-info").textContent =
      `Rata-rata korelasi Pearson antar share: ${data.mean_corr.toFixed(4)} (mendekati 0.0 menunjukkan share saling independen)`;

    const grid = $("enc-shares-grid");
    grid.innerHTML = "";
    data.shares.forEach((share) => {
      const card = document.createElement("div");
      card.className = "share-card";

      const head = document.createElement("div");
      head.className = "share-card-head";
      const titleSpan = document.createElement("span");
      titleSpan.textContent = `Share ${share.index}`;
      const entSpan = document.createElement("span");
      entSpan.className = "badge badge-teal";
      entSpan.textContent = `Entropi bit: ${share.bit_entropy.toFixed(4)}`;
      head.append(titleSpan, entSpan);

      const hexBox = document.createElement("div");
      hexBox.className = "share-hex mono";
      hexBox.textContent = share.hex;

      const actions = document.createElement("div");
      actions.className = "share-actions";

      const copyHexBtn = document.createElement("button");
      copyHexBtn.type = "button";
      copyHexBtn.className = "btn btn-sm btn-secondary";
      copyHexBtn.textContent = "Salin Hex";
      copyHexBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(share.hex).then(() => showToast(`Hex Share ${share.index} disalin`));
      });

      const dlLink = document.createElement("a");
      dlLink.className = "btn btn-sm btn-primary";
      dlLink.href = share.download_url;
      dlLink.download = share.filename;
      dlLink.textContent = `Unduh ${share.filename}`;

      actions.append(copyHexBtn, dlLink);
      card.append(head, hexBox, actions);
      grid.appendChild(card);
    });
  }

  $("btn-goto-decrypt").addEventListener("click", () => {
    switchTab("decrypt");
  });

  // --- Tab 2: Combine & Decrypt ---
  function syncSessionToDecryptTab(job) {
    $("dec-session-banner").classList.remove("hidden");
    $("dec-session-vault-name").textContent = job.vault_filename;
    $("dec-use-session-vault").checked = true;
    $("dec-manual-vault-wrap").classList.add("hidden");
    $("dec-expected-sha").value = job.original_sha256;

    $("mode-btn-session").classList.remove("hidden");
    setDecryptShareMode("session");

    const checksWrap = $("dec-session-share-checks");
    checksWrap.innerHTML = "";
    job.shares.forEach((s) => {
      const label = document.createElement("label");
      label.className = "check-chip";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = String(s.index);
      cb.checked = true;
      cb.addEventListener("change", updateNMinusOneHint);
      const txt = document.createElement("span");
      txt.textContent = `Share ${s.index} (${s.filename})`;
      label.append(cb, txt);
      checksWrap.appendChild(label);
    });
    updateNMinusOneHint();
  }

  function updateNMinusOneHint() {
    if (!state.lastJob) return;
    const total = state.lastJob.n_shares;
    const checkedCount = $("dec-session-share-checks").querySelectorAll("input:checked").length;
    const hintEl = $("dec-nminus1-hint");
    if (checkedCount < total) {
      hintEl.textContent =
        `Mode uji keamanan aktif: hanya ${checkedCount} dari ${total} share dipilih (seharusnya ditolak oleh verifikasi HMAC InvalidToken).`;
      hintEl.classList.remove("hidden");
    } else {
      hintEl.classList.add("hidden");
    }
  }

  $("dec-use-session-vault").addEventListener("change", (e) => {
    const useSession = e.target.checked;
    $("dec-manual-vault-wrap").classList.toggle("hidden", useSession);
    if (useSession && state.lastJob) {
      $("dec-expected-sha").value = state.lastJob.original_sha256;
    }
  });

  function setDecryptShareMode(mode) {
    state.decShareMode = mode;
    document.querySelectorAll(".mode-pill").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.mode === mode);
    });
    $("share-panel-session").classList.toggle("hidden", mode !== "session");
    $("share-panel-files").classList.toggle("hidden", mode !== "files");
    $("share-panel-hex").classList.toggle("hidden", mode !== "hex");
  }

  document.querySelectorAll(".mode-pill").forEach((btn) => {
    btn.addEventListener("click", () => setDecryptShareMode(btn.dataset.mode));
  });

  bindDropzone($("dec-vault-dropzone"), $("dec-vault-input"), (files) => {
    state.decVaultFile = files[0];
    $("dec-vault-label").textContent = `${state.decVaultFile.name} (${formatBytes(state.decVaultFile.size)})`;
  });

  bindDropzone($("dec-keys-dropzone"), $("dec-keys-input"), (files) => {
    state.decKeyFiles = files;
    const chips = $("dec-keys-chips");
    chips.innerHTML = "";
    files.forEach((f) => {
      const chip = document.createElement("span");
      chip.className = "file-chip";
      chip.textContent = `${f.name} (${f.size} B)`;
      chips.appendChild(chip);
    });
  });

  function addHexRow(defaultVal = "") {
    const container = $("dec-hex-rows");
    const row = document.createElement("div");
    row.className = "hex-row";

    const input = document.createElement("input");
    input.type = "text";
    input.className = "input mono dec-hex-input";
    input.placeholder = "Tempel 64 karakter hex share...";
    input.value = defaultVal;

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn btn-sm btn-secondary";
    removeBtn.textContent = "Hapus";
    removeBtn.addEventListener("click", () => {
      if (container.children.length > 1) {
        row.remove();
      } else {
        input.value = "";
      }
    });

    row.append(input, removeBtn);
    container.appendChild(row);
  }

  for (let i = 0; i < 3; i += 1) {
    addHexRow();
  }
  $("btn-add-hex-row").addEventListener("click", () => addHexRow());

  $("dec-submit-btn").addEventListener("click", async () => {
    const errEl = $("dec-error");
    errEl.classList.add("hidden");
    $("dec-result-ok").classList.add("hidden");
    $("dec-result-rejected").classList.add("hidden");

    const formData = new FormData();
    const useSessionVault = state.lastJob && $("dec-use-session-vault").checked;

    if (useSessionVault) {
      formData.append("use_job_id", state.lastJob.job_id);
    } else if (state.decVaultFile) {
      formData.append("vault_file", state.decVaultFile);
    } else {
      errEl.textContent = "Silakan pilih atau unggah berkas .vault terlebih dahulu.";
      errEl.classList.remove("hidden");
      return;
    }

    if (state.decShareMode === "session" && state.lastJob) {
      if (!useSessionVault) {
        formData.append("use_job_id", state.lastJob.job_id);
      }
      const selected = Array.from(
        $("dec-session-share-checks").querySelectorAll("input:checked")
      ).map((el) => Number(el.value));
      formData.append("session_share_indices", JSON.stringify(selected));
    } else if (state.decShareMode === "files") {
      state.decKeyFiles.forEach((f) => formData.append("share_files", f));
    } else {
      const hexValues = Array.from(document.querySelectorAll(".dec-hex-input"))
        .map((el) => el.value.trim())
        .filter(Boolean);
      formData.append("share_hexes", JSON.stringify(hexValues));
    }

    formData.append("simulate_tamper", $("dec-simulate-tamper").checked ? "true" : "false");
    formData.append("expected_sha256", $("dec-expected-sha").value.trim());

    const refInput = $("dec-ref-file");
    if (refInput.files && refInput.files[0]) {
      formData.append("ref_file", refInput.files[0]);
    }

    const btn = $("dec-submit-btn");
    btn.disabled = true;
    btn.textContent = "Menggabungkan Share & Memverifikasi HMAC...";

    try {
      const resp = await fetch("/api/decrypt", { method: "POST", body: formData });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "Gagal memproses dekripsi.");
      }

      if (data.status === "rejected") {
        $("dec-reject-msg").textContent = data.message;
        $("dec-result-rejected").classList.remove("hidden");
      } else {
        renderDecryptSuccess(data);
      }
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    } finally {
      btn.disabled = false;
      btn.textContent = "Gabungkan Share & Dekripsi Berkas";
    }
  });

  function renderDecryptSuccess(data) {
    $("dec-result-ok").classList.remove("hidden");

    if (data.hash_match === true) {
      $("dec-kpi-hash").textContent = "True (Identik)";
    } else if (data.hash_match === false) {
      $("dec-kpi-hash").textContent = "False (Berbeda)";
    } else {
      $("dec-kpi-hash").textContent = "N/A (Tanpa Ref)";
    }

    $("dec-kpi-ber").textContent = data.ber_pct === null ? "N/A" : `${data.ber_pct.toFixed(1)}%`;
    $("dec-kpi-comb").textContent = `${data.comb_ms.toFixed(4)} ms`;
    $("dec-kpi-dec").textContent = `${data.dec_ms.toFixed(3)} ms`;

    $("dec-sha256").textContent = data.recovered_sha256;
    $("dec-preview-kind").textContent = data.preview.kind;
    $("dec-preview-text").textContent = data.preview.text;

    const dlBtn = $("dec-download-recovered");
    dlBtn.href = data.download_url;
    dlBtn.download = data.recovered_filename;
    dlBtn.textContent = `Unduh Berkas Hasil Pemulihan (${data.recovered_filename})`;
  }

  // --- Tab 3: Benchmark 10 Payload ---
  async function loadCachedBenchmark() {
    try {
      const resp = await fetch("/api/benchmark/cached");
      const data = await resp.json();
      if (data.available) {
        $("bench-source-note").textContent =
          "Menampilkan hasil benchmark tersimpan (outputs/benchmark_10_payload.csv). Klik \"Jalankan Benchmark Otomatis\" untuk pengujian langsung.";
        $("bench-source-note").classList.remove("hidden");
        renderBenchmarkData(data.rows, data.summary, data.timestamp, data.chart_urls, data.csv_url);
      }
    } catch (_) {
      // Ignore initial load failure if cache not ready
    }
  }

  $("bench-run-btn").addEventListener("click", () => {
    const mode = document.querySelector('input[name="bench-mode"]:checked').value;
    const btn = $("bench-run-btn");
    btn.disabled = true;
    btn.textContent = "Sedang Menguji Payload...";

    const progressWrap = $("bench-progress-wrap");
    progressWrap.classList.remove("hidden");
    $("bench-source-note").classList.add("hidden");
    $("bench-progress-fill").style.width = "0%";
    $("bench-progress-pct").textContent = "0%";
    $("bench-progress-text").textContent = "Memulai benchmark...";

    const source = new EventSource(`/api/benchmark/stream?mode=${encodeURIComponent(mode)}`);
    source.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      const pct = Math.round((payload.done / payload.total) * 100);
      $("bench-progress-fill").style.width = `${pct}%`;
      $("bench-progress-pct").textContent = `${pct}%`;
      $("bench-progress-text").textContent = payload.message;

      if (payload.type === "done") {
        source.close();
        btn.disabled = false;
        btn.textContent = "Jalankan Benchmark Otomatis";
        renderBenchmarkData(payload.rows, payload.summary, payload.timestamp, payload.chart_urls, payload.csv_url);
        showToast("Benchmark selesai dan grafik diperbarui");
      }
    };
    source.onerror = () => {
      source.close();
      btn.disabled = false;
      btn.textContent = "Jalankan Benchmark Otomatis";
      showToast("Koneksi streaming benchmark terputus");
    };
  });

  function renderBenchmarkData(rows, summary, timestamp, chartUrls, csvUrl) {
    $("bench-results").classList.remove("hidden");
    const csvBtn = $("bench-csv-btn");
    csvBtn.href = csvUrl || "/api/benchmark/csv";
    csvBtn.classList.remove("hidden");

    $("bkpi-hash").textContent = `${summary.hash_ok}/${summary.total_payloads}`;
    $("bkpi-ber").textContent = `${summary.max_ber.toFixed(1)}%`;
    $("bkpi-blocked").textContent = `${summary.blocked_ok}/${summary.total_payloads}`;
    $("bkpi-entropy").textContent = `${summary.ct_entropy_min.toFixed(4)}–${summary.ct_entropy_max.toFixed(4)}`;
    $("bkpi-xor").textContent = `${summary.xor_max_ms.toFixed(4)} ms`;

    const table = $("bench-table");
    const thead = table.querySelector("thead");
    const tbody = table.querySelector("tbody");
    thead.innerHTML = "";
    tbody.innerHTML = "";

    if (rows.length > 0) {
      const cols = Object.keys(rows[0]);
      const headRow = document.createElement("tr");
      cols.forEach((col) => {
        const th = document.createElement("th");
        th.textContent = col;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);

      rows.forEach((row) => {
        const tr = document.createElement("tr");
        cols.forEach((col) => {
          const td = document.createElement("td");
          const val = row[col];
          if (typeof val === "boolean") {
            const badge = document.createElement("span");
            badge.className = `badge ${val ? "badge-pass" : "badge-fail"}`;
            badge.textContent = val ? "True" : "False";
            td.appendChild(badge);
          } else {
            td.textContent = String(val);
          }
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    }

    const q = timestamp ? `?t=${timestamp}` : `?t=${Date.now()}`;
    const urls = chartUrls || {
      timing: "/outputs/chart_timing.png",
      entropy: "/outputs/chart_entropy.png",
      correlation: "/outputs/chart_correlation.png",
      expansion: "/outputs/chart_expansion.png",
    };
    $("chart-timing").src = `${urls.timing}${q}`;
    $("chart-entropy").src = `${urls.entropy}${q}`;
    $("chart-correlation").src = `${urls.correlation}${q}`;
    $("chart-expansion").src = `${urls.expansion}${q}`;
  }

  // --- Lightbox Modal ---
  document.querySelectorAll(".chart-card").forEach((card) => {
    card.addEventListener("click", () => {
      const img = card.querySelector("img");
      const cap = card.querySelector("figcaption");
      if (!img || !img.src) return;
      $("modal-img").src = img.src;
      $("modal-caption").textContent = cap ? cap.textContent : "";
      $("chart-modal").classList.remove("hidden");
    });
  });

  function closeModal() {
    $("chart-modal").classList.add("hidden");
  }

  $("modal-close-btn").addEventListener("click", closeModal);
  document.querySelector(".modal-backdrop").addEventListener("click", closeModal);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  loadCachedBenchmark();
})();
