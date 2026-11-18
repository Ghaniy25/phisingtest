# Smart Phishing Detection System

Sistem deteksi URL phishing berbasis **FastAPI**, **Algoritma Klasifikasi Heuristik & DNS/SSL (Modul `Detection/`)**, **Google Cloud Firestore**, dan **Single-Page Dashboard (HTML5 + Tailwind CSS)** dengan dukungan deployment **Apache2** & **Docker**.

---

## 📁 Struktur Direktori Proyek

```text
.
├── backend/
│   ├── main.py                         # Entry point FastAPI, CORS, security headers & routing
│   ├── schemas.py                      # Validasi Pydantic v2 (anti-SSRF & schema respons)
│   ├── security.py                     # Rate limiter per IP, admin X-API-Key, & scan_id validator
│   ├── requirements.txt                # Dependensi Python (FastAPI, Uvicorn, Pydantic, Firestore)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── classifier_service.py       # Integrasi algoritma Zikra (fitur leksikal + DNS/SSL)
│   │   ├── firestore_service.py        # Integrasi Google Cloud Firestore + in-memory fallback
│   │   └── mock_classifier.py          # Wrapper kompatibilitas menuju classifier_service
│   └── routes/
│       ├── __init__.py
│       ├── health.py                   # GET /api/v1/health
│       ├── analyze.py                  # POST /api/v1/analyze
│       ├── history.py                  # GET/DELETE /api/v1/history & GET /api/v1/history/{scan_id}
│       └── stats.py                    # GET /api/v1/statistics
├── Detection/                          # Modul klasifikasi Zikra (lexical features & passive DNS/SSL)
│   ├── feature_extraction.py
│   ├── domain_checker.py
│   └── classifier.py
├── frontend/
│   └── index.html                      # Responsive Single-Page Dashboard
├── docs/
│   ├── API_AND_DEPLOYMENT_GUIDE.md     # Panduan API, keamanan, Postman & handover Firestore VPS
│   └── Smart_Phishing_Detection.postman_collection.json
├── tests/
│   └── test_api.py                     # Unit test suite (classifier, validasi, Firestore fallback, security)
├── phishing-app.conf                   # Konfigurasi Apache2 VirtualHost Reverse Proxy
├── Dockerfile & docker-compose.prod.yml
└── .env.example
```

---

## 🚀 Menjalankan Secara Lokal

### 1. Persiapan Environment Backend
Pastikan Python 3.9+ sudah terpasang:

```bash
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

pip install -r backend/requirements.txt
```

### 2. Jalankan Server FastAPI
```bash
python backend/main.py
```
*(Atau `uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`)*

* **Dashboard Web UI**: `http://127.0.0.1:8000/`
* **Swagger Docs**: `http://127.0.0.1:8000/docs`
* **Health Check**: `http://127.0.0.1:8000/api/v1/health`

*(Saat dijalankan secara lokal tanpa kredensial GCP, backend otomatis menggunakan `in_memory_fallback` storage. Ketika `GOOGLE_APPLICATION_CREDENTIALS` dan `FIRESTORE_PROJECT_ID` dikonfigurasi di `.env` / VPS, backend otomatis terhubung ke Google Cloud Firestore).*

---

## 📡 Ringkasan Endpoint API v1

| Metode | Endpoint | Proteksi | Deskripsi |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | - | Status service, classifier, dan backend storage |
| `POST` | `/api/v1/analyze` | Rate Limit + Validasi URL & SSRF | Analisis URL dengan modul `Detection/` & simpan hasil |
| `GET` | `/api/v1/history` | Rate Limit (`?limit=1..100`) | Daftar riwayat pemindaian terbaru |
| `GET` | `/api/v1/history/{scan_id}` | Rate Limit + Format `scan-xxxxxxxx` | Detail fitur & info domain untuk 1 sesi scan |
| `DELETE` | `/api/v1/history` | Header `X-API-Key` Admin | Menghapus seluruh riwayat pemindaian |
| `GET` | `/api/v1/statistics` | Rate Limit | Agregasi jumlah `SAFE`, `SUSPICIOUS`, `PHISHING` |

---

## 🧪 Pengujian

1. **Automated Unit Tests**:
   ```bash
   python -m unittest tests/test_api.py -v
   ```
2. **Pengujian Postman**:
   Import koleksi [`docs/Smart_Phishing_Detection.postman_collection.json`](./docs/Smart_Phishing_Detection.postman_collection.json) ke Postman.
3. **Panduan Lengkap & Setup VPS Firestore**:
   Lihat [`docs/API_AND_DEPLOYMENT_GUIDE.md`](./docs/API_AND_DEPLOYMENT_GUIDE.md).
