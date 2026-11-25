# 🎙️ Panduan & Script Presentasi: Frontend & Backend Architecture
## Proyek: Smart Phishing Detection System
**Mata Kuliah:** Cloud Computing & Rekayasa Keamanan Siber (AMJ)  
**Peran:** Frontend & Backend Engineer (Orang 2)  
**Target Infrastruktur:** Linux VPS (IP: `10.33.109.93`), Apache2 Reverse Proxy, Docker Engine, FastAPI, Tailwind SPA.

---

## 📋 Daftar Isi
1. [Ringkasan Peran & Spesifikasi Arsitektur](#1-ringkasan-peran--spesifikasi-arsitektur)
2. [Script Lengkap Pembicara (Speaker Notes)](#2-script-lengkap-pembicara-speaker-notes)
   - [A. Pembukaan & Perkenalan Diri (±1 Menit)](#a-pembukaan--perkenalan-diri-1-menit)
   - [B. Backend & Arsitektur Cloud (±2.5 Menit)](#b-backend--arsitektur-cloud-25-menit)
   - [C. Frontend SPA & Visualisasi Telemetri (±1.5 Menit)](#c-frontend-spa--visualisasi-telemetri-15-menit)
   - [D. Skenario Live Demo & Pengujian Sistem (±2 Menit)](#d-skenario-live-demo--pengujian-sistem-2-menit)
   - [E. Penutup (±30 Detik)](#e-penutup-30-detik)
3. [Tabel Aturan Klasifikasi PRD & Heuristik Deteksi](#3-tabel-aturan-klasifikasi-prd--heuristik-deteksi)
4. [Kompilasi Pertanyaan Dosen & Kunci Jawaban (Q&A Cheat Sheet)](#4-kompilasi-pertanyaan-dosen--kunci-jawaban-qa-cheat-sheet)

---

## 1. Ringkasan Peran & Spesifikasi Arsitektur

Sebagai **Frontend & Backend Engineer**, poin-poin utama yang dibangun meliputi:
* **Backend:** RESTful API asinkron menggunakan **FastAPI (Python 3.11)**, arsitektur ASGI murni, schema validation via Pydantic v2.
* **Deteksi:** Ekstraksi 10 fitur heuristik real-time, evaluasi 5 aturan PRD (`R-01` s/d `R-05`), penilaian risiko transparan `0 - 100`.
* **Keamanan Cloud:** Proteksi Anti-SSRF (memblokir Private RFC1918 & Cloud Metadata `169.254.169.254`), Sliding-Window Rate Limiting, API Key admin security headers middleware.
* **Ketahanan Data (Storage Resilience):** Dual-tier database storage: Google Cloud Firestore (Primary) dengan *Graceful Degradation* otomatis ke SQLite lokal di dalam Docker Volume (`/app/data`).
* **Infrastruktur VPS:** Reverse Proxy Apache2 (Port 80) meneruskan request ke Docker Container Uvicorn (Port internal 8000).
* **Frontend:** Single Page Application (SPA) responsif berkinerja tinggi, radial SVG threat score gauge, matriks telemetri 10 fitur, tabel riwayat interaktif, dan ekspor CSV kompatibel Microsoft Excel & Google Sheets.

---

## 2. Script Lengkap Pembicara (Speaker Notes)

### A. Pembukaan & Perkenalan Diri (±1 Menit)
*(Sikap percaya diri, tatap penguji/audiens)*

> "Selamat pagi / siang kepada Bapak/Ibu Dosen pengampu dan rekan-rekan sekalian.
> 
> Perkenalkan, saya **[Sebutkan Nama Anda]**. Dalam tim pengembang **Smart Phishing Detection System**, tanggung jawab utama saya adalah merancang dan mengimplementasikan **Arsitektur Backend API**, **Antarmuka Frontend Dashboard**, serta memastikan orkestrasi sistem berjalan andal di atas infrastruktur **Cloud VPS**.
> 
> Pada sesi ini, saya akan menjelaskan bagaimana prinsip-prinsip komputasi awan—seperti *Containerization*, *Decoupled Architecture*, *High Availability*, dan *Cloud Security Controls*—kami terapkan secara nyata untuk mendeteksi ancaman phishing berbasis rekayasa sosial dan manipulasi domain secara real-time."

---

### B. Backend & Arsitektur Cloud (±2.5 Menit)
*(Arahkan layar ke diagram arsitektur atau dokumentasi API di `/docs`)*

> "Secara arsitektur cloud, sistem kami dibangun dengan beberapa pilar utama:
> 
> **1. Kontainerisasi dengan Docker (Environment Parity):**  
> Seluruh backend FastAPI berjalan di dalam kontainer Docker terisolasi. Hal ini memastikan konsistensi lingkungan pengembangan dari laptop hingga server produksi VPS kampus tanpa risiko konflik pustaka.
> 
> **2. Apache Reverse Proxy ke Uvicorn ASGI:**  
> Pada tingkat sistem operasi VPS, kami mengonfigurasi Apache2 sebagai *Reverse Proxy* di port 80. Apache menyajikan berkas antarmuka statis sekaligus mem-proxy lalu lintas API ke Uvicorn di port internal 8000. Konfigurasi ini menyembunyikan port aplikasi internal dari publik dan meningkatkan efisiensi I/O.
> 
> **3. Ketahanan Penyimpanan Cloud & Graceful Degradation:**  
> Sesuai standar ketersediaan tinggi (*High Availability*), backend kami terintegrasi dengan Google Cloud Firestore. Namun, apabila koneksi cloud terputus atau kredensial cloud belum aktif, backend memiliki mekanisme *Graceful Degradation* otomatis ke database SQLite lokal di dalam Docker Volume (`/app/data`). Dengan demikian, sistem tidak pernah *crash* dan riwayat audit pemindaian tetap persisten saat kontainer di-restart.
> 
> **4. Kontrol Keamanan Cloud (Anti-SSRF & Rate Limiting):**  
> Karena sistem bertugas memindai URL eksternal, risiko keamanan tertinggi adalah **SSRF (Server-Side Request Forgery)**. Kami mengimplementasikan filter keamanan ketat: memblokir akses ke alamat IP privat lokal (RFC1918), loopback `127.0.0.1`, dan alamat sensitif *Cloud Metadata* (`169.254.169.254`). Kami juga menyematkan *Sliding-Window Rate Limiting* per alamat IP klien untuk mencegah serangan DoS, serta otentikasi API Key khusus untuk operasi administratif."

---

### C. Frontend SPA & Visualisasi Telemetri (±1.5 Menit)
*(Arahkan browser ke halaman utama dashboard `http://10.33.109.93/`)*

> "Beralih ke sisi antarmuka, tantangan utama kami adalah menyajikan hasil telemetri keamanan yang rumit menjadi visualisasi yang intuitif dan cepat dipahami:
> 
> **1. Arsitektur Single-Page Application (SPA) Berkecepatan Tinggi:**  
> Kami membangun frontend menggunakan Vanilla JavaScript modern dan Tailwind CSS tanpa dependensi framework runtime yang berat. Hasilnya, ukuran berkas sangat ringkas, waktu render di bawah 1 detik, dan konsumsi memori browser sangat efisien.
> 
> **2. Komponen Visualisasi Utama:**  
> * **Hero Scanner Full-Width:** Form input lega dan memanjang yang memudahkan analis keamanan menginput dan membaca URL target yang sangat panjang.
> * **Radial SVG Threat Gauge:** Lingkaran skor risiko dinamis 0–100 dengan indikator warna berbasis ambang batas (Hijau: Aman 0–29, Kuning: Waspada 30–59, Merah: Phishing 60–100).
> * **10-Feature Matrix Cards:** Matriks 10 kartu telemetri yang menguraikan hasil analisis leksikal, anomali IP, usia domain RDAP, kesamaan brand resmi, status DNS, dan enkripsi SSL.
> * **Triggered Rules Badge:** Penjelasan transparan tentang aturan PRD apa yang terpicu.
> * **Ekspor CSV Berstandar Excel:** Riwayat pemindaian dapat diunduh dalam format CSV yang dilengkapi UTF-8 BOM dan pemisah kolom otomatis untuk kebutuhan audit keamanan."

---

### D. Skenario Live Demo & Pengujian Sistem (±2 Menit)
*(Lakukan pengujian langsung di hadapan penguji)*

#### Pengujian 1: URL Legitimate / Resmi
* **Input:** `https://www.google.com`
* **Penjelasan:**  
  > "Pertama, kita uji domain resmi `google.com`. Sistem memverifikasi struktur leksikal yang bersih, protokol HTTPS aktif, resolusi DNS valid, dan tidak ada indikator manipulasi. Sistem menetapkan vonis **SAFE** dengan skor risiko **0/100** berdasarkan aturan **R-05**."

#### Pengujian 2: URL Terindikasi Phishing (IP Anomaly + Phishing Keywords)
* **Input:** `http://192.168.1.100/update-akun/login-verifikasi/`
* **Penjelasan:**  
  > "Kedua, kita simulasikan tautan phishing rekayasa sosial. Tautan ini menggunakan alamat IP mentah tanpa nama domain, tanpa enkripsi HTTPS, serta memuat kata kunci sensitif 'login', 'verifikasi', dan 'update'.  
  > Sistem secara instan mendeteksi anomali IP, menandai protokol non-HTTPS, memicu aturan **R-01 & R-04**, dan menetapkan klasifikasi **PHISHING** dengan skor risiko tinggi **(80/100)** di zona merah."

#### Pengujian 3: Sinkronisasi Riwayat & Ekspor CSV
* **Aksi:** Klik salah satu baris riwayat di tabel bawah, lalu klik tombol **Ekspor CSV**.
* **Penjelasan:**  
  > "Setiap hasil pemindaian langsung dicatat ke basis data persisten. Analis dapat mengklik baris riwayat mana pun untuk memunculkan kembali rincian telemetri secara instan, serta mengunduh seluruh berkas audit ke format CSV yang siap dibuka di Microsoft Excel."

---

### E. Penutup (±30 Detik)
> "Sebagai kesimpulan, integrasi Frontend dan Backend ini berhasil membuktikan keunggulan arsitektur cloud: modularitas melalui Docker, ketahanan penyimpanan data berlapis, perlindungan jaringan terhadap eksploitasi SSRF, serta penyajian data yang transparan bagi pengguna akhir.
> 
> Demikian paparan dari saya mengenai arsitektur Frontend dan Backend. Terima kasih atas perhatian Bapak/Ibu Dosen dan rekan-rekan sekalian, waktu selanjutnya saya buka untuk sesi tanya jawab."

---

## 3. Tabel Aturan Klasifikasi PRD & Heuristik Deteksi

| Kode Aturan | Kategori | Kondisi Pemicu Utama | Skor Risiko | Klasifikasi |
| :---: | :---: | :--- | :---: | :---: |
| **R-01** | *Credential & IP Phishing* | Host berupa IP mentah, atau URL memuat simbol `@` (userinfo spoofing). | +50 s/d +70 | **PHISHING** (Skor ≥ 60) |
| **R-02** | *Subdomain & Protocol Risk* | Subdomain bertingkat banyak (≥ 3 level) atau kombinasi protokol HTTP tanpa enkripsi. | +20 s/d +40 | **SUSPICIOUS / PHISHING** |
| **R-03** | *Typosquatting & Brand Spoofing* | Nama domain memiliki kemiripan ejaan (*Levenshtein distance*) dengan domain resmi yang dilindungi. | +50 | **PHISHING** (Skor ≥ 60) |
| **R-04** | *High-Risk Accumulation* | Akumulasi indikator mencurigakan: URL panjang, domain baru (< 30 hari), kata kunci login/verify, kegagalan DNS/SSL. | Akumulatif | **SUSPICIOUS** (30–59) / **PHISHING** (≥ 60) |
| **R-05** | *Safe Baseline* | Tidak ada indikator berbahaya, DNS teresolusi valid, SSL/TLS valid, reputasi bersih. | 0 s/d 29 | **SAFE** |

---

## 4. Kompilasi Pertanyaan Dosen & Kunci Jawaban (Q&A Cheat Sheet)

### Pertanyaan 1: Mengapa menggunakan kontainerisasi Docker daripada instalasi bare-metal di VPS?
> **Jawaban:**  
> "Docker memberikan isolasi lingkungan (*environment parity*), sehingga dependensi Python 3.11 dan modul deteksi terisolasi dari host OS Ubuntu di VPS. Selain itu, Docker mempermudah *scaling* dan *restart policy*, serta membatasi hak akses aplikasi terhadap kernel host demi alasan keamanan."

### Pertanyaan 2: Apa langkah mitigasi arsitektur terhadap serangan SSRF (Server-Side Request Forgery)?
> **Jawaban:**  
> "Karena sistem kami menerima input URL bebas dari publik dan melakukan resolusi jaringan, kami memvalidasi URL di tingkat backend sebelum melakukan koneksi soket apa pun. Backend menolak skema selain `http/https`, menolak resolusi ke alamat IP privat (RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback `127.0.0.1`, dan endpoint metadata cloud `169.254.169.254`."

### Pertanyaan 3: Bagaimana sistem memastikan data riwayat tidak hilang jika Google Firestore bermasalah?
> **Jawaban:**  
> "Kami mengimplementasikan pola arsitektur *Graceful Degradation*. Backend secara cerdas mendeteksi ketersediaan Google Cloud Firestore. Jika koneksi atau kredensial Firestore tidak tersedia, modul penyimpanan otomatis mengalihkan operasi baca-tulis ke SQLite lokal di `/app/data/phishing_history.db` yang terikat pada Docker Volume persisten, sehingga tidak ada *data loss* maupun *downtime* layanan."

### Pertanyaan 4: Mengapa memilih Single-Page Application (SPA) murni daripada framework seperti Next.js atau React?
> **Jawaban:**  
> "Untuk aplikasi audit keamanan operasional, faktor utama adalah kecepatan muat, keandalan, dan kesederhanaan *pipeline deployment*. Menggunakan Vanilla JS dan Tailwind CSS memungkinkan berkas disajikan langsung oleh Apache web server dengan waktu respons instan, tanpa memerlukan proses *Node.js build* yang memakan CPU dan memori berlebih di VPS."

### Pertanyaan 5: Bagaimana backend menangani batas beban request (Rate Limiting)?
> **Jawaban:**  
> "Kami menerapkan mekanisme *Sliding-Window Rate Limiting* di tingkat ASGI middleware FastAPI. Setiap IP klien dibatasi maksimal 30 permintaan per menit untuk endpoint pemindaian (`/api/v1/analyze`) dan 60 permintaan per menit untuk pembacaan riwayat, mencegah potensi serangan DoS atau eksploitasi berlebihan terhadap resolver DNS sistem."
