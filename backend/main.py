import os
import sys
from pathlib import Path

# Ensure project root is in sys.path to prevent 'ModuleNotFoundError: No module named backend'
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.routes import analyze, health, history, stats

app = FastAPI(
    title="Smart Phishing Detection API",
    description="Web Server & Zikra Heuristic Phishing Classifier Backend with Firestore Integration",
    version="2.0.0",
)

# Parse CORS origins from environment variable
_raw_origins = os.getenv("CORS_ORIGINS", "*").strip()
_cors_origins = [origin.strip() for origin in _raw_origins.split(",") if origin.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=(_cors_origins != ["*"]),
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


class SecurityHeadersMiddleware:
    """Pure ASGI middleware attaching standard HTTP security headers to every response."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


app.add_middleware(SecurityHeadersMiddleware)


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
        "role": "Web Server & Backend API",
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
        "version": "2.0.0",
        "api_v1_prefix": "/api/v1",
        "docs_url": "/docs",
        "health_check": "/api/v1/health",
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run("backend.main:app", host=host, port=port, reload=True)
