from fastapi import APIRouter
from backend.schemas import StatsResponse
from backend.services.mock_classifier import MOCK_HISTORY_DB

router = APIRouter(prefix="/statistics", tags=["Statistics"])


@router.get("", response_model=StatsResponse, summary="Get Aggregate Phishing Statistics")
def get_statistics():
    """Dynamically aggregate total, safe, suspicious, and phishing scan counts."""
    total = len(MOCK_HISTORY_DB)
    safe = sum(1 for item in MOCK_HISTORY_DB if item.classification == "SAFE")
    suspicious = sum(1 for item in MOCK_HISTORY_DB if item.classification == "SUSPICIOUS")
    phishing = sum(1 for item in MOCK_HISTORY_DB if item.classification == "PHISHING")

    return StatsResponse(
        total_scans=total,
        safe_count=safe,
        suspicious_count=suspicious,
        phishing_count=phishing,
    )

