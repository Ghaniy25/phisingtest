from fastapi import APIRouter, Depends

from backend.schemas import StatsResponse
from backend.security import rate_limit_history
from backend.services import firestore_service

router = APIRouter(prefix="/statistics", tags=["Statistics"])


@router.get(
    "",
    response_model=StatsResponse,
    dependencies=[Depends(rate_limit_history)],
    summary="Get Aggregate Phishing Statistics",
)
def get_statistics():
    """Dynamically aggregate total, safe, suspicious, and phishing scan counts."""
    return firestore_service.get_statistics()
