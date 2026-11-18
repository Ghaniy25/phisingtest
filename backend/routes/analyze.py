from fastapi import APIRouter, Depends, status

from backend.schemas import URLCheckRequest, URLCheckResponse
from backend.security import rate_limit_analyze
from backend.services.classifier_service import analyze_url

router = APIRouter(tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=URLCheckResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_analyze)],
    summary="Analyze URL for Phishing Threats",
)
def analyze_target_url(payload: URLCheckRequest):
    """Analyze a validated URL using Zikra's feature extraction and passive DNS/SSL engine."""
    return analyze_url(payload.url)
