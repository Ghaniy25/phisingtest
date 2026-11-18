"""
Compatibility wrapper: delegates directly to Zikra's classifier_service and firestore_service.
Mock classification logic has been replaced with Detection/classifier.py integration.
"""

from backend.services.classifier_service import analyze_url
from backend.services.firestore_service import (
    _IN_MEMORY_DB as MOCK_HISTORY_DB,
    clear_history as clear_history_database,
)

__all__ = ["analyze_url", "MOCK_HISTORY_DB", "clear_history_database"]
