# Context File: Prototype Aplikasi CAPSTONE 2026 (Fernet + XOR Secret Sharing)

Dokumen ini berisi seluruh konteks arsitektur, algoritma, hasil pengujian, dan spesifikasi kebutuhan untuk membangun **prototype aplikasi demo** tugas akhir/kompetisi **CAPSTONE 2026** (Skema *Project Based Expo* — Cabang **Kriptografi dan Keamanan Data**, Universitas Negeri Malang).

---

## 1. Ringkasan Proyek
- **Judul Karya:** Sistem Pengamanan Berkas Terdistribusi Menggunakan Enkripsi Fernet dan Pembagian Kunci Rahasia Berbasis Operasi Bitwise
- **Kombinasi Metode (Wajib Tepat 2 Metode):**
  1. **Kriptografi:** `Fernet` (`cryptography.fernet.Fernet`) — enkripsi simetris terautentikasi berbasis **AES-128-CBC** + *padding* PKCS7 + segel integritas **HMAC-SHA256** (*Encrypt-then-MAC*), dengan keluaran berformat *URL-safe Base64*.
  2. **Secret Sharing:** `XOR Secret Sharing` skema **$n$-dari-$n$ ($n=3$)** — memecah kunci master 32 byte menjadi 3 bagian independen menggunakan operasi bitwise `XOR`.
- **Media:** Berkas dokumen maupun biner arbitrer (non-citra, mendukung `.txt`, `.pdf`, `.docx`, `.zip`, `.sql`, `.bin`, dll).
- **Ketua Tim:** Muhammad Al Bukhari (NIM. 240535610175) — kelompok 3 orang.

---

## 2. Arsitektur & Kontrak Logika Inti (Sudah Teruji)

Prototype aplikasi **wajib** mempertahankan alur dan logika kriptografi berikut (tidak perlu mengganti dengan Shamir polinomial atau steganografi citra):

1. **Proses Pengamanan (Encrypt & Split):**
   - Bangkitkan kunci master acak 32 byte (`os.urandom(32)`).
   - Encode kunci ke *URL-safe Base64* (`base64.urlsafe_b64encode(raw_key)`) dan enkripsi berkas menggunakan `Fernet(key).encrypt(raw_data)` menghasilkan berkas `.vault`.
   - Pecah `raw_key` (32 byte) menjadi $n=3$ *share* berukuran masing-masing 32 byte:
     - $K_1, K_2$: 32 byte acak dari `os.urandom(32)`.
     - $K_3 = K \oplus K_1 \oplus K_2$.
2. **Proses Pemulihan (Combine & Decrypt):**
   - Kumpulkan *share* kunci yang tersedia lalu gabungkan via `XOR`: $K_{\text{pulih}} = K_1 \oplus K_2 \oplus K_3$.
   - Encode $K_{\text{pulih}}$ ke *URL-safe Base64* dan dekripsi berkas `.vault` via `Fernet.decrypt(token)`.
   - **Validasi Keamanan:** Karena `Fernet` menerapkan *Verify-before-Decrypt*, jika hanya $n-1$ share (2 dari 3) yang dimasukkan atau ada 1 bit saja pada berkas `.vault` yang dimodifikasi, proses dekripsi **harus gagal** dengan galat `InvalidToken`.

### Referensi Kode Inti Python
```python
import os, base64, hashlib
import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from scipy.stats import entropy, pearsonr
from scipy.spatial.distance import hamming

def xor_split(secret_bytes: bytes, n: int = 3) -> list[bytes]:
    secret_arr = np.frombuffer(secret_bytes, dtype=np.uint8)
    shares = []
    xor_accum = secret_arr.copy()
    for _ in range(n - 1):
        rand_share = np.frombuffer(os.urandom(len(secret_bytes)), dtype=np.uint8)
        shares.append(rand_share.tobytes())
        xor_accum = np.bitwise_xor(xor_accum, rand_share)
    shares.append(xor_accum.tobytes())
    return shares

def xor_combine(shares: list[bytes]) -> bytes:
    result = np.zeros(len(shares[0]), dtype=np.uint8)
    for s in shares:
        result = np.bitwise_xor(result, np.frombuffer(s, dtype=np.uint8))
    return result.tobytes()
```

---

## 3. Kebutuhan Fungsional Prototype Aplikasi Demo

Bangun prototype aplikasi yang interaktif, mudah didemokan di depan dewan juri, dan memiliki **3 fitur/halaman utama**:

### Fitur 1: Amankan Berkas (Encrypt & Split)
- **Input:** Pengguna mengunggah 1 berkas sembarang (misal `.txt`, `.pdf`, `.docx`, `.png`, `.zip`) dan dapat melihat/mengatur jumlah share ($n=3$ default).
- **Proses:** Enkripsi berkas dengan `Fernet` dan pecah kunci 32 byte menjadi 3 share.
- **Output UI:**
  - Ringkasan perbandingan ukuran asli vs ukuran terenkripsi (`.vault`) beserta persentase ekspansi (~33,33% untuk file besar karena Base64).
  - Nilai hash **SHA-256** berkas asli.
  - Cuplikan teks token terenkripsi (`gAAAAAB...`) untuk membuktikan isi berkas tidak terbaca.
  - Tombol unduh berkas `.vault` serta masing-masing *share* (`share_1.key`, `share_2.key`, `share_3.key` atau teks hex-nya).

### Fitur 2: Pulihkan Berkas & Simulasi Uji Keamanan (Combine & Decrypt)
- **Input:** Pengguna mengunggah berkas `.vault` dan memasukkan/mengunggah $m$ buah *share* (bisa 3 share lengkap, atau sengaja hanya 2 share untuk demo uji $n-1$).
- **Output UI:**
  - **Jika semua 3 share valid:** Tampilkan status sukses, rekonstruksi berkas asli, tampilkan **SHA-256 Hash Match = True** & **BER = 0.0%**, serta sediakan tombol unduh berkas hasil pemulihan.
  - **Jika kurang dari 3 share (uji $n-1$) atau share/token rusak:** Tampilkan peringatan keamanan tegas bahwa akses ditolak oleh verifikasi HMAC (`InvalidToken`) tanpa membocorkan data.

### Fitur 3: Panel Evaluasi & Benchmark Otomatis 10 Payload
- Menjalankan pengujian otomatis pada **10 ukuran payload** (`1 KB`, `10 KB`, `100 KB`, `500 KB`, `1 MB`, `5 MB`, `10 MB`, `20 MB`, `35 MB`, `50 MB`).
- Menghitung dan menampilkan dalam bentuk **tabel interaktif** dan **grafik**:
  - `Hash Match` (SHA-256, harus `True` 100%)
  - `BER (%)` via `scipy.spatial.distance.hamming` (harus `0.0%`)
  - `n-1 Blocked` (uji 2 dari 3 share, harus `True` 10/10)
  - `Entropi Ciphertext (bit/byte)` via `scipy.stats.entropy(..., base=2)` (mendekati `8.0`)
  - `Entropi Bit Share` (mendekati `1.0`)
  - `Korelasi Antar Share` via `scipy.stats.pearsonr` (mendekati `0.0`)
  - `Ekspansi Ukuran (%)` dan `Waktu Proses (ms)` per tahap (`Enc`, `Split`, `Comb`, `Dec`).
- Sediakan tombol ekspor hasil tabel ke `.csv`.

---

## 4. Rekomendasi Tech Stack Prototype
- **Opsi Tercepat & Paling Stabil untuk Demo:** **Python + Streamlit** (`streamlit`, `cryptography`, `numpy`, `scipy`, `pandas`, `matplotlib`) — seluruh kode backend Python di atas dapat langsung diintegrasikan ke antarmuka web lokal tanpa perlu membangun API terpisah.
- **Opsi Alternatif (Web Terpisah):** Backend **FastAPI** (Python) + Frontend **React / Next.js** (Tailwind CSS), dengan logika kriptografi dan metrik tetap berjalan di backend Python.

---

## 5. Acuan Hasil Pengujian Sebelumnya (Baseline)
Sebagai patokan validasi saat mengembangkan aplikasi, eksekusi `fernet_xor_secret_sharing.ipynb` sebelumnya telah menghasilkan metrik berikut:
- **Integritas:** 10/10 payload (`1 KB`–`50 MB`) menghasilkan `Hash_Match = True` dan `BER = 0.0%`.
- **Uji $n-1$ Share:** 10/10 payload berhasil diblokir (`InvalidToken`) saat hanya 2 dari 3 share digunakan.
- **Keacakan & Independensi:** Entropi *ciphertext* `7.8089`–`7.9999 bit/byte`; entropi bit share `0.9920`–`0.9989`; korelasi antar share berkisar di sekitar nol (`-0.20` s.d. `+0.34`).
- **Kinerja:** Waktu `XOR Split` & `Combine` konstan `< 0.15 ms`; total waktu pemrosesan file `50 MB` sekitar `~1.1 detik`; ekspansi ukuran berkas besar stabil di `33.33%`.

---

## 6. Instruksi untuk AI Coding Assistant
1. Gunakan struktur arsitektur dan fungsi inti di atas tanpa mengubah metode menjadi steganografi atau Shamir polinomial.
2. Pastikan aplikasi memiliki tampilan antarmuka yang bersih, responsif, berbahasa Indonesia, dan siap didemokan langsung (*live demo*) di hadapan dewan juri CAPSTONE 2026.
3. Tangani berkas biner besar (hingga 50 MB) dengan aman di memori atau *temporary buffer*, serta tampilkan pesan status/error yang informatif bagi pengguna.
