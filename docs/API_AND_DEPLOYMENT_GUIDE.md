# Panduan API, 10 Fitur PRD, 5 Aturan Klasifikasi, Firestore & Handover VPS

Dokumen ini menjelaskan implementasi lengkap **Smart Phishing Detection System v2.0** sesuai spesifikasi PRD:
1. **10 Fitur Deteksi Lengkap**: URL Length, IP Address (IPv4/IPv6), Special Characters (`@`, `-`, `%`), Subdomain (Public Suffix aware), HTTPS, Domain Age (RDAP aktual, tanpa simulasi), Suspicious Keywords, URL Shortening, Domain Similarity (Typosquatting/Homoglyph), dan SSL/TLS Certificate.
2. **5 Aturan Utama Rule-Based Classification (`R-01` s/d `R-05`)** dengan perhitungan `risk_score` (0–100) transparan, `technical_status` (`complete` / `inconclusive`), dan `classification_reason`.
3. **Perlindungan Anti-SSRF & DNS Rebinding** sebelum melakukan koneksi keluar.
4. **Google Cloud Firestore** dengan fallback lokal persisten **SQLite** untuk development/testing serta dukungan pagination (`limit` & `offset`).

---

## 1. 10 Fitur Deteksi & Bobot Skor Risiko (0–100)

| No | Fitur PRD | Field di API (`features` / `domain_info`) | Kondisi Berisiko & Poin |
| :-: | :--- | :--- | :--- |
| 1 | **URL Length** | `url_length`, `is_long_url` | `> 75` karakter (`+20`), `55 - 75` karakter (`+10`) |
| 2 | **IP Address** | `has_ip` | Penggunaan IPv4/IPv6 langsung sebagai host (`+40`) |
| 3 | **Special Characters** | `has_at`, `hyphen_count`, `percent_count`, `special_char_count` | Karakter `@` (`+30`), `>= 3` hyphen (`+20`), `1 - 2` hyphen (`+5`), `>= 3` `%` (`+10`) |
| 4 | **Subdomain** | `subdomain_count`, `registrable_domain` | Public suffix aware (`.co.id`, `.ac.id`, dll.): `>= 3` level (`+20`), `2` level (`+10`) |
| 5 | **HTTPS** | `is_https`, `has_https` | Tidak menggunakan HTTPS (`+10`) |
| 6 | **Domain Age (RDAP)** | `domain_age_days`, `domain_age_status`, `registration_date` | Aktual via RDAP (`null`/`unavailable` jika tidak tersedia): `< 30` hari (`+25`), `30 - 89` hari (`+15`) |
| 7 | **Suspicious Keywords** | `suspicious_keywords_found` | `>= 4` keyword (`+25`), `2 - 3` keyword (`+15`), `1` keyword (`+5`) |
| 8 | **URL Shortening** | `is_shortened` | Menggunakan layanan pemendek URL (`+30`) |
| 9 | **Domain Similarity** | `similarity_detected`, `similar_to_domain`, `similarity_score` | Menyerupai domain resmi dengan ejaan berbeda/typosquatting (`+75`) |
| 10 | **SSL Certificate & DNS** | `ssl_status`, `ssl_valid`, `ssl_expiry`, `dns_resolved` | SSL `Invalid / Self-Signed` atau `Expired` (`+30`), HTTPS tanpa SSL valid (`+15`), DNS gagal resolve (`+15`) |

---

## 2. 5 Aturan Klasifikasi PRD (`R-01` s/d `R-05`)

* **`R-01` (PHISHING)**: URL menggunakan IP Address dan memiliki karakter/pola mencurigakan (`risk_score >= 80`).
* **`R-02` (SUSPICIOUS)**: Domain berusia baru (`< 90` hari dari RDAP) dan memiliki banyak subdomain (`>= 2` level) (`risk_score >= 45`).
* **`R-03` (PHISHING)**: Domain memiliki kemiripan dengan domain resmi (`PROTECTED_DOMAINS`) tetapi menggunakan ejaan berbeda (`risk_score >= 80`).
* **`R-04` (SUSPICIOUS / Indikator Pendukung)**: URL memiliki karakteristik mencurigakan atau pemeriksaan teknis DNS/SSL belum lengkap (`inconclusive`).
* **`R-05` (SAFE)**: URL tidak memenuhi aturan berbahaya (`risk_score < 30`) dan pemeriksaan teknis (DNS & SSL/TLS) berhasil divalidasi.

---

## 3. Endpoint REST API `/api/v1`

| Method | Endpoint | Parameter / Proteksi | Deskripsi |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | - | Status aplikasi, classifier, dan backend database (`firestore` / `sqlite_local_fallback`) |
| `POST` | `/api/v1/analyze` | Rate limit (`30/m`), validasi URL & SSRF | Ekstraksi 10 fitur, analisis DNS/RDAP/SSL, evaluasi `R-01..R-05`, dan simpan histori |
| `GET` | `/api/v1/history` | `?limit=20&offset=0`, Rate limit (`60/m`) | Ambil riwayat pemeriksaan terbaru dengan pagination |
| `GET` | `/api/v1/history/{scan_id}` | Validasi `^scan-[a-f0-9]{8}$` | Ambil detail lengkap pemeriksaan berdasarkan ID |
| `DELETE` | `/api/v1/history` | Header `X-API-Key` (`ADMIN_API_KEY`) | Hapus seluruh riwayat pemeriksaan (khusus admin) |
| `GET` | `/api/v1/statistics` | Rate limit (`60/m`) | Hitung statistik `total_scans`, `safe_count`, `suspicious_count`, `phishing_count` |

---

## 4. Handover Deployment VPS & Firestore (Untuk Lu)

1. Simpan file JSON Service Account di host VPS (misal `/etc/phishing-detector/firestore-key.json`, `chmod 600`), **jangan pernah** di-commit ke GitHub atau di-copy ke `Dockerfile`.
2. Konfigurasikan variabel di `.env` VPS:
   * `FIRESTORE_PROJECT_ID`
   * `FIRESTORE_COLLECTION=phishing_scans`
   * `GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/firestore-key.json`
   * `ADMIN_API_KEY=<random-secret>`
   * `CORS_ORIGINS=https://domain-anda.com`
3. Jalankan container produksi dengan `docker compose -f docker-compose.prod.yml up -d`.
