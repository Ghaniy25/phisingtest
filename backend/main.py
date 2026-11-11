import sys
from pathlib import Path

# Ensure project root is in sys.path to prevent 'ModuleNotFoundError: No module named backend'
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.routes import health, analyze, history, stats

app = FastAPI(
    title="Smart Phishing Detection API",
    description="Orang 2 Web Server & Mock Classifier Backend for Phishing Threat Analysis",
    version="1.0.0",
)

# Enable CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Main API v1 Router prefix
api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health.router)
api_v1_router.include_router(analyze.router)
api_v1_router.include_router(history.router)
api_v1_router.include_router(stats.router)

# Mount API Router
app.include_router(api_v1_router)

# Frontend Path Resolution
FRONTEND_DIR = ROOT_DIR / "frontend"


@app.get("/", tags=["Dashboard"])
def serve_dashboard():
    """Serve the single-page frontend application or API overview fallback."""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "system": "Smart Phishing Detection System",
        "role": "Orang 2 (Web Server & Backend)",
        "status": "online",
        "api_v1_prefix": "/api/v1",
        "docs_url": "/docs",
        "health_check": "/api/v1/health",
    }


@app.get("/api", tags=["Root"])
def api_info():
    """API metadata and endpoints index."""
    return {
        "system": "Smart Phishing Detection System",
        "version": "1.0.0",
        "api_v1_prefix": "/api/v1",
        "docs_url": "/docs",
        "health_check": "/api/v1/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
