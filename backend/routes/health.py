from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
def get_health_status():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "ok",
        "service": "phishing-detector-backend-mock",
    }

