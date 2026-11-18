from fastapi import APIRouter

from backend.services import firestore_service

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Backend & Storage Health Check")
def get_health_status():
    """Health check endpoint reporting service readiness, classifier engine, and storage backend."""
    return {
        "status": "ok",
        "service": "phishing-detector-backend",
        "classifier": "zikra-heuristic-dns-ssl",
        "storage": firestore_service.get_storage_status(),
    }
