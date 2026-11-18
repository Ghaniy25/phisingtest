from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.schemas import URLCheckResponse
from backend.security import rate_limit_history, validate_scan_id, verify_admin_api_key
from backend.services import firestore_service

router = APIRouter(prefix="/history", tags=["History"])


@router.get(
    "",
    response_model=List[URLCheckResponse],
    dependencies=[Depends(rate_limit_history)],
    summary="Get Recent Scan History with Pagination",
)
def get_scan_history(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of items to return"),
    offset: int = Query(default=0, ge=0, le=10000, description="Number of items to skip for pagination"),
):
    """Retrieve scan history sorted by newest first with limit and offset pagination."""
    return firestore_service.get_history(limit=limit, offset=offset)


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_admin_api_key)],
    summary="Clear Scan History (Admin Only)",
)
def clear_history():
    """Clear all records from storage (requires X-API-Key administrator header)."""
    count = firestore_service.clear_history()
    return {
        "message": "Scan history successfully cleared.",
        "deleted_count": count,
    }


@router.get(
    "/{scan_id}",
    response_model=URLCheckResponse,
    dependencies=[Depends(rate_limit_history)],
    summary="Get Scan Details by ID",
)
def get_scan_by_id(scan_id: str):
    """Retrieve complete feature details and verdict for a specific scan ID."""
    validated_id = validate_scan_id(scan_id)
    record = firestore_service.get_scan_by_id(validated_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan session with ID '{validated_id}' not found.",
        )
    return record
