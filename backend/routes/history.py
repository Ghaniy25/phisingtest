from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.schemas import URLCheckResponse
from backend.services.mock_classifier import (
    MOCK_HISTORY_DB,
    reset_history_database,
    clear_history_database,
)

router = APIRouter(prefix="/history", tags=["History"])


@router.get(
    "",
    response_model=List[URLCheckResponse],
    summary="Get Recent Scan History",
)
def get_scan_history(limit: Optional[int] = Query(default=20, ge=1, le=100)):
    """Retrieve scan history sorted by newest first."""
    return MOCK_HISTORY_DB[:limit]


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    summary="Clear Scan History",
)
def clear_history():
    """Clear all records from the in-memory database."""
    count = clear_history_database()
    return {
        "message": "Scan history successfully cleared.",
        "deleted_count": count,
    }


@router.post(
    "/reset",
    status_code=status.HTTP_200_OK,
    summary="Reset Scan History to Default Samples",
)
def reset_history():
    """Reset history database back to seeded mock sample scans."""
    count = reset_history_database()
    return {
        "message": "Scan history reset to default demonstration data.",
        "current_count": count,
    }


@router.get(
    "/{scan_id}",
    response_model=URLCheckResponse,
    summary="Get Scan Details by ID",
)
def get_scan_by_id(scan_id: str):
    """Retrieve complete feature details and verdict for a specific scan ID."""
    for record in MOCK_HISTORY_DB:
        if record.scan_id == scan_id:
            return record

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scan session with ID '{scan_id}' not found.",
    )
