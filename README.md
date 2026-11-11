# Smart Phishing Detection System
## Codebase & Server Architecture: Orang 2 (Web Server & Backend)

Prototype standalone web server dan backend untuk sistem deteksi phishing cerdas, dilengkapi dengan **FastAPI**, **Mock Classification Engine**, **Single-Page HTML Dashboard**, dan **Konfigurasi Reverse Proxy Apache2**.

---

## 📁 Struktur Direktori Proyek

```text
.
├── backend/
│   ├── main.py                     # Entry point FastAPI, CORS, & API v1 mounting
│   ├── schemas.py                  # Pydantic schemas untuk request, response, dan stats
│   ├── requirements.txt            # Dependensi Python
│   ├── services/
│   │   ├── __init__.py
│   │   └── mock_classifier.py      # Heuristic & Intelligent Mock Classification Engine
│   └── routes/
│       ├── __init__.py
│       ├── health.py               # GET /api/v1/health
│       ├── analyze.py              # POST /api/v1/analyze
│       ├── history.py              # GET /api/v1/history & GET /api/v1/history/{scan_id}
│       └── stats.py                # GET /api/v1/statistics
├── frontend/
│   └── index.html                  # Responsive Single-Page Dashboard (Tailwind CSS + Lucide)
├── apache/
│   └── phishing-app.conf           # Konfigurasi Apache2 VirtualHost Reverse Proxy
└── README.md                       # Dokumentasi dan panduan deployment
```

---

## 🚀 Panduan Menjalankan Secara Lokal (Tonight's Goal)

### 1. Persiapan Environment Backend
Pastikan Python 3.9+ sudah terpasang di sistem.

```bash
# Buat virtual environment (opsional namun disarankan)
python -m venv venv

# Aktivasi virtual environment:
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependensi
pip install -r backend/requirements.txt
```

### 2. Jalankan Server FastAPI
Jalankan Uvicorn dari root direktori proyek:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Backend akan aktif di:
- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

### 3. Membuka Frontend
- Buka file `frontend/index.html` langsung di peramban web (browser).
- Frontend secara otomatis melakukan pengecekan kesehatan API ke `http://127.0.0.1:8000/api/v1/health`.
- Status badge di navbar akan berubah menjadi **🟢 API Connected**.

---

## 📡 Dokumentasi Endpoint API v1

| Metode | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Pengecekan status ketersediaan backend service |
| `POST` | `/api/v1/analyze` | Menganalisis URL, menghitung skor risiko, dan memberikan klasifikasi |
| `GET` | `/api/v1/history` | Mengambil daftar riwayat scan terbaru (opsional: `?limit=10`) |
| `GET` | `/api/v1/history/{scan_id}` | Mengambil detail fitur spesifik dari satu sesi scan |
| `GET` | `/api/v1/statistics` | Menghitung agregasi scan: Total, Safe, Suspicious, Phishing |

### Contoh Request & Response POST `/api/v1/analyze`

**Request Body:**
```json
{
  "url": "http://192.168.1.105/login-verify.php"
}
```

**Response Body:**
```json
{
  "scan_id": "scan-e4b2a190",
  "url": "http://192.168.1.105/login-verify.php",
  "classification": "PHISHING",
  "risk_score": 93,
  "scanned_at": "2026-11-11T12:00:00.000000+00:00",
  "features": {
    "url_length": 38,
    "has_ip": true,
    "has_https": false,
    "subdomain_count": 0,
    "suspicious_keywords_found": ["login", "verify"],
    "is_shortened": false,
    "domain_age_days": 7,
    "ssl_valid": false
  },
  "rules_triggered": [
    "R-01: Direct IP address or high-risk keywords used",
    "R-03: Multiple domain anomalies detected",
    "R-06: Non-secure transmission protocol (HTTP)"
  ]
}
```

---

## 🌐 Panduan Konfigurasi Apache2 (Production / Orang 3 Handover)

Untuk mendeploy frontend dan reverse-proxying API di server Linux (Ubuntu/Debian) dengan Apache2:

1. **Aktifkan modul Apache yang diperlukan**:
   ```bash
   sudo a2enmod proxy proxy_http headers rewrite
   ```

2. **Salin file frontend ke DocumentRoot**:
   ```bash
   sudo mkdir -p /var/www/html/phishing-app
   sudo cp frontend/index.html /var/www/html/phishing-app/
   ```

3. **Salin konfigurasi VirtualHost**:
   ```bash
   sudo cp apache/phishing-app.conf /etc/apache2/sites-available/phishing-app.conf
   sudo a2ensite phishing-app.conf
   sudo a2dissite 000-default.conf # Opsional jika menggantikan default site
   ```

4. **Uji konfigurasi dan restart Apache**:
   ```bash
   sudo apache2ctl configtest
   sudo systemctl restart apache2
   ```

---

## 🤝 Rencana Integrasi Tim

1. **Orang 1 (Model Klasifikasi AI / ML)**:
   - Ganti implementasi `analyze_url()` di `backend/services/mock_classifier.py` dengan model inference sesungguhnya (e.g., joblib/pickle model scikit-learn / PyTorch / ONNX).
   - Skema API Pydantic di `backend/schemas.py` sudah dioptimalkan agar model Orang 1 dapat langsung di-plug tanpa mengubah antarmuka frontend.

2. **Orang 3 (Infrastruktur Cloud & DevOps)**:
   - File konfigurasi Apache `apache/phishing-app.conf` dan struktur backend siap dijadikan service systemd (`/etc/systemd/system/phishing-backend.service`) atau di-containerize menggunakan Docker/Kubernetes.

