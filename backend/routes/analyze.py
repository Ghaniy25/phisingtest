from fastapi import APIRouter, HTTPException, status
from backend.schemas import URLCheckRequest, URLCheckResponse
from backend.services.mock_classifier import analyze_url

router = APIRouter(tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=URLCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing Threats",
)
def analyze_target_url(payload: URLCheckRequest):
    """Analyze a given URL with heuristic and mock classification logic."""
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty.",
        )
    return analyze_url(target_url)

