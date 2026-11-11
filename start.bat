@echo off
echo ========================================================
echo  Smart Phishing Detection System - Orang 2 Backend
echo ========================================================
echo Checking Python environment...
python -c "import fastapi, uvicorn, pydantic" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Missing dependencies. Installing from backend/requirements.txt...
    pip install -r backend/requirements.txt
)

echo Starting FastAPI server with Uvicorn on http://127.0.0.1:8000...
echo - API Base URL: http://127.0.0.1:8000/api/v1
echo - Dashboard UI: http://127.0.0.1:8000/
echo - Swagger Docs: http://127.0.0.1:8000/docs
echo ========================================================
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

