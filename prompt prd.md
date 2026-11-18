# FULL BACKEND AUDIT, DEVELOPMENT, AND INTEGRATION — SMART PHISHING DETECTION SYSTEM

Bertindaklah sebagai Senior Backend Engineer, Python Developer, Cloud Engineer, dan Software Tester. Tugasmu adalah melakukan audit, memperbaiki, dan menyelesaikan implementasi backend Smart Phishing Detection System berdasarkan PRD yang tersedia.

Jangan hanya memberikan rekomendasi atau contoh kode. Lakukan perubahan langsung pada source code project, jalankan pengujian, perbaiki error yang ditemukan, dan buat laporan hasil implementasi.

## 1. KONDISI PROJECT SAAT INI

Project: Smart Phishing Detection System  
Backend: Python + FastAPI  
Deployment: Docker Compose pada VPS Linux  
Application Server: Uvicorn  
Direktori project: phisingtest  
Direktori backend: backend/

Struktur backend saat ini:

- backend/main.py
- backend/schemas.py
- backend/routes/analyze.py
- backend/routes/health.py
- backend/routes/history.py
- backend/routes/stats.py
- backend/services/mock_classifier.py
- backend/requirements.txt

Kondisi implementasi saat ini:
- API sudah berjalan.
- Docker container berstatus healthy.
- Endpoint /api/v1/health memberikan HTTP 200.
- Backend masih menggunakan mock_classifier.py.
- Klasifikasi masih menggunakan rule-based sederhana.
- Domain age dan SSL validity masih disimulasikan.
- Riwayat pemeriksaan menggunakan penyimpanan in-memory.
- Belum ditemukan implementasi seluruh 10 fitur dalam PRD.
- Dependency backend saat ini hanya FastAPI, Uvicorn, dan Pydantic.

Catatan deployment:
Container backend saat ini berjalan melalui Docker Compose dan memetakan 127.0.0.1:8000 ke port 8000 container.

Jangan mengasumsikan seluruh file project hanya berada di direktori backend. Periksa struktur project secara menyeluruh terlebih dahulu.

## 2. ACUAN METODE DETEKSI

WAJIB mengikuti PRD.

Metode utama adalah RULE-BASED CLASSIFICATION.

Jangan mengganti metode utama menjadi:
- Machine Learning.
- Deep Learning.
- Neural Network.
- Model AI klasifikasi.

Sistem menggunakan ekstraksi karakteristik URL, informasi domain, pemeriksaan SSL/TLS, dan evaluasi aturan untuk menghasilkan klasifikasi:

1. SAFE
2. SUSPICIOUS
3. PHISHING

## 3. IMPLEMENTASI 10 FITUR DETEKSI

Implementasikan seluruh fitur berikut:

1. URL Length
   - Menghitung panjang URL.
   - Menentukan indikator URL yang terlalu panjang.

2. IP Address
   - Mendeteksi penggunaan alamat IPv4 atau IPv6 langsung sebagai host.
   - Membedakan hostname dengan alamat IP.

3. Special Characters
   - Menganalisis karakter khusus seperti @, -, %, dan simbol lain yang relevan.
   - Jangan menganggap setiap penggunaan karakter khusus otomatis berbahaya.

4. Subdomain
   - Menghitung jumlah subdomain.
   - Menganalisis pola hostname secara benar.
   - Jangan menggunakan pemisahan string sederhana tanpa mempertimbangkan public suffix.

5. HTTPS
   - Memeriksa apakah URL menggunakan protokol HTTPS.
   - Jangan menganggap HTTPS menjamin website aman.

6. Domain Age
   - Mengambil informasi usia domain menggunakan RDAP atau sumber WHOIS yang sesuai.
   - Menghitung usia berdasarkan tanggal registrasi jika tersedia.
   - Jika data tidak tersedia, kembalikan status unavailable/null.
   - Jangan menggunakan nilai domain age simulasi.

7. Suspicious Keywords
   - Mendeteksi kata mencurigakan seperti login, verify, secure, account, bank, credential, dan token.
   - Simpan daftar keyword yang ditemukan.
   - Hindari menjadikan satu keyword sebagai bukti mutlak phishing.

8. URL Shortening
   - Mendeteksi layanan URL shortener yang dikenal.
   - Pisahkan deteksi URL shortener dari pemeriksaan tujuan redirect.
   - Jangan mengikuti redirect secara otomatis tanpa validasi keamanan.

9. Domain Similarity
   - Mendeteksi kemiripan hostname dengan domain resmi.
   - Gunakan daftar domain resmi yang dapat dikonfigurasi.
   - Pertimbangkan typo, karakter pengganti, dan homoglyph secara wajar.
   - Jangan mengklaim domain mirip sebagai phishing tanpa indikator pendukung.
   - Hindari false positive pada domain yang tidak memiliki hubungan.

10. SSL Certificate
    - Lakukan pemeriksaan sertifikat SSL/TLS secara aktual jika koneksi memungkinkan.
    - Periksa validitas sertifikat, masa berlaku, dan hostname.
    - Bedakan status valid, invalid, unavailable, dan error.
    - Jangan menyimpulkan sertifikat valid hanya karena URL diawali HTTPS.

Setiap fitur harus memiliki hasil ekstraksi yang dapat ditampilkan melalui API.

## 4. IMPLEMENTASI RULE-BASED CLASSIFICATION

Implementasikan lima aturan utama sesuai PRD:

R-01:
URL menggunakan IP Address dan memiliki karakter mencurigakan.
Hasil: PHISHING.

R-02:
Domain baru dan memiliki banyak subdomain.
Hasil: SUSPICIOUS.

R-03:
Domain memiliki kemiripan dengan domain resmi tetapi menggunakan ejaan berbeda.
Hasil: PHISHING.

R-04:
URL memiliki karakteristik mencurigakan tetapi belum memenuhi aturan phishing.
Hasil: SUSPICIOUS.

R-05:
URL tidak memenuhi aturan berbahaya dan pemeriksaan teknis berhasil.
Hasil: SAFE.

Persyaratan tambahan:
- Aturan harus dapat dipelihara dan diperbarui.
- Setiap klasifikasi harus menyertakan rules_triggered.
- Tampilkan alasan klasifikasi secara jelas.
- Buat risk_score dalam rentang 0–100.
- Dokumentasikan cara perhitungan risk_score secara transparan.
- Jangan menyebut risk_score sebagai probabilitas statistik.
- HTTPS tidak boleh menjadi satu-satunya penentu keamanan.
- Data domain atau SSL yang unavailable tidak boleh dianggap sebagai bukti aman.
- Jika hasil pemeriksaan teknis tidak lengkap, pertimbangkan status pemeriksaan sebagai inconclusive dan jelaskan alasannya.

## 5. DOMAIN DAN SSL ANALYSIS

Buat service terpisah untuk pemeriksaan domain dan SSL/TLS.

Persyaratan:
- Timeout koneksi.
- Error handling.
- Status unavailable ketika data tidak dapat diperoleh.
- Tidak membuat aplikasi menunggu terlalu lama.
- Tidak mengarang data domain.
- Tidak mengarang status SSL.

Keamanan sangat penting karena backend memproses URL dari pengguna.

Implementasikan perlindungan SSRF:
- Validasi URL sebelum melakukan koneksi.
- Hanya izinkan skema HTTP dan HTTPS.
- Blokir localhost, private IP, loopback, link-local, multicast, reserved IP, dan alamat internal.
- Periksa hasil DNS resolution sebelum koneksi.
- Cegah DNS rebinding sejauh memungkinkan.
- Jangan mengakses cloud metadata endpoint.
- Jika redirect digunakan, validasi ulang setiap tujuan redirect.
- Terapkan timeout dan batas ukuran respons.
- Jangan mengambil atau mengeksekusi konten website.
- Jangan mengirim credential atau informasi sensitif ke URL tujuan.

Jangan membuat mekanisme yang dapat digunakan untuk memindai jaringan internal.

## 6. DATABASE DAN SCAN HISTORY

PRD menetapkan database cloud, dengan Firestore sebagai rekomendasi teknologi.

Audit konfigurasi project terlebih dahulu:
- Apakah Firestore sudah dikonfigurasi?
- Apakah service account tersedia?
- Apakah environment variable sudah disiapkan?
- Apakah sudah ada database lain yang digunakan?

Jika Firestore sudah tersedia, implementasikan integrasi Firestore untuk menyimpan:
- scan_id
- url
- url_length
- has_ip
- has_https
- domain_age
- ssl_valid
- features
- classification
- risk_score
- rules_triggered
- scanned_at

Persyaratan:
- History tidak boleh lagi bergantung pada variabel global in-memory.
- Data harus tetap tersedia setelah container restart.
- Gunakan pagination atau limit untuk pengambilan histori.
- Sediakan detail pemeriksaan berdasarkan ID.
- Sediakan penghapusan atau reset histori sesuai kebutuhan akses admin.
- Statistik harus dihitung dari data yang tersimpan.

Jika kredensial Firestore tidak tersedia:
- Jangan membuat credential palsu.
- Jangan mengklaim integrasi Firestore sudah berhasil.
- Buat adapter database yang jelas dan dapat dikonfigurasi.
- Sediakan penyimpanan lokal persisten hanya untuk development/testing jika diperlukan.
- Dokumentasikan dengan jelas bagian yang masih membutuhkan konfigurasi cloud.
- Jangan menggunakan mock sebagai penyimpanan produksi.

## 7. REST API

Pertahankan prefix API /api/v1.

Pastikan endpoint berikut tersedia dan berfungsi:

POST /api/v1/analyze
- Menerima URL.
- Memvalidasi URL.
- Melakukan ekstraksi fitur.
- Melakukan pemeriksaan domain dan SSL.
- Melakukan klasifikasi.
- Menyimpan histori.
- Mengembalikan hasil analisis.

GET /api/v1/history
- Mengambil histori pemeriksaan.
- Mendukung limit dan pagination.

GET /api/v1/history/{id}
- Mengambil detail pemeriksaan.

GET /api/v1/statistics
- Mengambil statistik klasifikasi.

GET /api/v1/health
- Memeriksa kesehatan backend.
- Bedakan kesehatan aplikasi dan status dependency database jika memungkinkan.

Gunakan Pydantic schema yang konsisten.
Gunakan HTTP status code yang tepat.
Berikan pesan error yang mudah dipahami.
Pastikan respons API konsisten dan terdokumentasi.

## 8. KOMPATIBILITAS FRONTEND

Sebelum mengubah schema dan endpoint:
- Periksa seluruh file frontend.
- Periksa struktur request dan response yang digunakan frontend.
- Periksa dashboard, halaman analisis, histori, statistik, dan autentikasi jika tersedia.
- Pertahankan nama field dan format respons yang masih digunakan frontend.
- Jika perlu mengubah struktur respons, perbarui seluruh pemanggil API secara konsisten.
- Jangan menghilangkan fitur frontend yang sudah berjalan.

Jangan mengubah desain UI tanpa alasan teknis yang kuat.

## 9. SECURITY DAN RELIABILITY

Implementasikan:
- URL validation.
- Penanganan input tidak valid.
- SSRF protection.
- Timeout.
- Error handling.
- CORS sesuai konfigurasi.
- Rate limiting jika sesuai arsitektur project.
- Batas ukuran input.
- Pengelolaan credential melalui environment variable.
- Tidak mengekspos secret atau private key.
- Logging yang tidak mencatat credential atau informasi sensitif.
- Penanganan kegagalan database dan layanan RDAP/SSL.

Jangan mengubah file .env produksi atau menampilkan isi secret.

## 10. TESTING

Buat dan jalankan automated tests.

Minimal pengujian:
- URL valid.
- URL invalid.
- URL menggunakan IP address.
- URL menggunakan karakter @.
- URL dengan banyak subdomain.
- URL dengan suspicious keywords.
- URL shortener.
- Domain baru.
- Domain similarity.
- Sertifikat SSL valid.
- Sertifikat SSL invalid atau expired menggunakan fixture pengujian yang aman.
- Data domain unavailable.
- Klasifikasi SAFE.
- Klasifikasi SUSPICIOUS.
- Klasifikasi PHISHING.
- Penyimpanan histori.
- Pengambilan histori.
- Statistik.
- Error handling.
- SSRF protection.
- Integrasi API.

Jangan mengakses website phishing aktif untuk melakukan pengujian.

Gunakan fixture, mock pada unit test, atau domain pengujian yang aman. Mock hanya diperbolehkan untuk pengujian, bukan sebagai hasil pemeriksaan produksi.

Jangan mengklaim target accuracy 90% tercapai tanpa dataset pengujian terpisah yang berlabel dan hasil evaluasi aktual.

Jika dataset tersedia, lakukan evaluasi accuracy, precision, recall, dan F1-score.

## 11. DOCKER DAN DEPLOYMENT

Periksa:
- Dockerfile.
- docker-compose.yml.
- backend/requirements.txt.
- Environment configuration.
- Volume.
- Network.
- Health check.

Perbarui dependency sesuai implementasi sebenarnya.

Pastikan aplikasi dapat berjalan melalui Docker Compose.

Jangan:
- Menghapus container produksi.
- Menghapus volume.
- Menghapus database.
- Mengubah port publik tanpa alasan.
- Mengganti konfigurasi VPS secara sembarangan.
- Menjalankan docker compose down -v.
- Menimpa environment variable produksi.
- Melakukan deployment produksi otomatis tanpa persetujuan.

Selesaikan perubahan source code dan pengujian terlebih dahulu. Setelah itu berikan instruksi deployment yang aman.

## 12. STRUKTUR KODE

Pisahkan tanggung jawab setiap service agar mudah dipelihara.

Contoh struktur yang dapat disesuaikan:

backend/
  main.py
  schemas.py
  routes/
    analyze.py
    health.py
    history.py
    stats.py
  services/
    url_validator.py
    feature_extractor.py
    domain_analyzer.py
    ssl_analyzer.py
    rule_classifier.py
    risk_assessor.py
  database/
    firestore.py
    repository.py
  tests/

Jangan memaksakan struktur ini jika project sudah memiliki pola arsitektur yang lebih baik.

Hapus atau pensiunkan mock_classifier.py hanya setelah seluruh pemanggilnya sudah dipindahkan dan pengujian berhasil.

## 13. TAHAP PELAKSANAAN

Lakukan seluruh pekerjaan berikut:

1. Audit seluruh struktur project dan konfigurasi.
2. Identifikasi ketergantungan frontend terhadap API.
3. Buat rencana perubahan singkat.
4. Implementasikan seluruh fitur backend.
5. Integrasikan domain analysis dan SSL/TLS.
6. Implementasikan rule-based classification sesuai PRD.
7. Implementasikan risk assessment.
8. Implementasikan database dan histori.
9. Sesuaikan seluruh endpoint.
10. Perbarui dependency dan Docker jika diperlukan.
11. Jalankan seluruh automated tests.
12. Perbaiki error yang ditemukan.
13. Jalankan pemeriksaan integrasi.
14. Buat dokumentasi konfigurasi dan deployment.

Jangan berhenti setelah hanya membuat struktur folder atau file kosong.

## 14. LAPORAN AKHIR

Setelah selesai, berikan laporan dengan format:

A. Perubahan file yang dilakukan.

B. Fitur yang berhasil diimplementasikan.

C. Fitur yang belum berhasil dan alasannya.

D. Database yang digunakan dan status integrasinya.

E. Hasil automated testing:
- Total test.
- Passed.
- Failed.
- Skipped.

F. Hasil pengujian endpoint API.

G. Status kompatibilitas frontend.

H. Perubahan Docker dan dependency.

I. Environment variable yang perlu dikonfigurasi tanpa menampilkan secret.

J. Langkah deployment ke VPS.

K. Risiko atau keterbatasan yang masih tersisa.

PENTING:
Jangan menyatakan fitur berhasil jika belum diuji. Bedakan implementasi yang sudah selesai, yang masih memerlukan konfigurasi, dan yang belum tersedia.

Target akhir adalah backend Smart Phishing Detection System yang mengikuti PRD, menggunakan rule-based classification, tidak lagi mengandalkan mock untuk proses produksi, dan terintegrasi dengan frontend serta layanan cloud yang benar-benar tersedia.