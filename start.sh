#!/usr/bin/env bash
set -e

echo "========================================================"
echo " Smart Phishing Detection System - Orang 2 Backend"
echo "========================================================"

# Check if required packages are installed
if ! python3 -c "import fastapi, uvicorn, pydantic" 2>/dev/null; then
    echo "[!] Installing dependencies from backend/requirements.txt..."
    pip3 install -r backend/requirements.txt
fi

echo "Starting FastAPI server with Uvicorn on http://127.0.0.1:8000..."
echo "- API Base URL: http://127.0.0.1:8000/api/v1"
echo "- Dashboard UI: http://127.0.0.1:8000/"
echo "- Swagger Docs: http://127.0.0.1:8000/docs"
echo "========================================================"

uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

