from contextlib import closing
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import List, Optional

from backend.schemas import StatsResponse, URLCheckResponse

logger = logging.getLogger("phishing_detector.firestore")

COLLECTION_NAME = os.getenv("FIRESTORE_COLLECTION", "phishing_scans")
DEFAULT_SQLITE_PATH = Path(__file__).resolve().parent.parent / "data" / "local_history.sqlite3"

# Compatibility reference kept in sync with persistent local SQLite store
_IN_MEMORY_DB: List[URLCheckResponse] = []

_db_client = None
_init_attempted = False
_sqlite_lock = threading.Lock()


def _get_sqlite_path() -> str:
    custom = os.getenv("LOCAL_DB_PATH", "").strip()
    if custom:
        if custom != ":memory:":
            Path(custom).parent.mkdir(parents=True, exist_ok=True)
        return custom
    DEFAULT_SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return str(DEFAULT_SQLITE_PATH)


def _init_sqlite_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS phishing_scans (
            scan_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            scanned_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scanned_at ON phishing_scans(scanned_at DESC)"
    )


def _get_firestore_client():
    """Lazily initialize Google Cloud Firestore client from environment variables."""
    global _db_client, _init_attempted
    if _init_attempted:
        return _db_client

    _init_attempted = True
    creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    project_id = (
        os.getenv("FIRESTORE_PROJECT_ID", "").strip()
        or os.getenv("GOOGLE_CLOUD_PROJECT", "").strip()
        or None
    )
    force_enable = os.getenv("FIRESTORE_FORCE_ENABLE", "false").lower() == "true"

    if not creds_path and not force_enable:
        logger.info(
            "GOOGLE_APPLICATION_CREDENTIALS tidak diset; menggunakan persistent SQLite local fallback."
        )
        return None

    if creds_path and not os.path.exists(creds_path):
        logger.warning(
            "File kredensial Firestore '%s' tidak ditemukan; menggunakan persistent SQLite local fallback.",
            creds_path,
        )
        return None

    try:
        from google.cloud import firestore  # type: ignore

        _db_client = firestore.Client(project=project_id) if project_id else firestore.Client()
        logger.info("Terhubung ke Google Cloud Firestore (collection='%s').", COLLECTION_NAME)
    except ImportError:
        logger.warning(
            "Paket 'google-cloud-firestore' belum terinstal; menggunakan persistent SQLite local fallback."
        )
        _db_client = None
    except Exception as exc:
        logger.error("Gagal menginisialisasi Firestore client: %s", exc)
        _db_client = None

    return _db_client


def reset_client_state():
    """Reset cached client initialization state (useful for testing)."""
    global _db_client, _init_attempted
    _db_client = None
    _init_attempted = False


def get_storage_status() -> dict:
    """Return active storage backend metadata for health checks."""
    client = _get_firestore_client()
    return {
        "backend": "firestore" if client is not None else "sqlite_local_fallback",
        "collection": COLLECTION_NAME,
        "firestore_configured": client is not None,
    }


def save_scan(record: URLCheckResponse) -> URLCheckResponse:
    """Persist a scan result to Firestore or the persistent SQLite local store."""
    client = _get_firestore_client()
    payload = record.model_dump()
    if client is not None:
        doc_ref = client.collection(COLLECTION_NAME).document(record.scan_id)
        doc_ref.set(payload)
        return record

    db_path = _get_sqlite_path()
    with _sqlite_lock:
        if db_path != ":memory:":
            with closing(sqlite3.connect(db_path)) as conn:
                _init_sqlite_table(conn)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO phishing_scans
                    (scan_id, url, classification, risk_score, scanned_at, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.scan_id,
                        record.url,
                        record.classification,
                        record.risk_score,
                        record.scanned_at,
                        json.dumps(payload),
                    ),
                )
                conn.commit()
        _IN_MEMORY_DB.insert(0, record)
    return record


def get_history(limit: int = 20, offset: int = 0) -> List[URLCheckResponse]:
    """Retrieve recent scan records sorted newest first with limit and offset pagination."""
    client = _get_firestore_client()
    if client is not None:
        from google.cloud import firestore  # type: ignore

        query = (
            client.collection(COLLECTION_NAME)
            .order_by("scanned_at", direction=firestore.Query.DESCENDING)
            .offset(offset)
            .limit(limit)
        )
        results: List[URLCheckResponse] = []
        for doc in query.stream():
            data = doc.to_dict()
            if data:
                results.append(URLCheckResponse(**data))
        return results

    db_path = _get_sqlite_path()
    with _sqlite_lock:
        if db_path != ":memory:" and os.path.exists(db_path):
            with closing(sqlite3.connect(db_path)) as conn:
                _init_sqlite_table(conn)
                cursor = conn.execute(
                    """
                    SELECT payload_json FROM phishing_scans
                    ORDER BY scanned_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
                rows = cursor.fetchall()
                return [URLCheckResponse(**json.loads(r[0])) for r in rows]

        return _IN_MEMORY_DB[offset : offset + limit]


def get_scan_by_id(scan_id: str) -> Optional[URLCheckResponse]:
    """Fetch a single scan record by its unique scan_id."""
    client = _get_firestore_client()
    if client is not None:
        doc = client.collection(COLLECTION_NAME).document(scan_id).get()
        if doc.exists:
            data = doc.to_dict()
            if data:
                return URLCheckResponse(**data)
        return None

    db_path = _get_sqlite_path()
    with _sqlite_lock:
        if db_path != ":memory:" and os.path.exists(db_path):
            with closing(sqlite3.connect(db_path)) as conn:
                _init_sqlite_table(conn)
                cursor = conn.execute(
                    "SELECT payload_json FROM phishing_scans WHERE scan_id = ?",
                    (scan_id,),
                )
                row = cursor.fetchone()
                if row:
                    return URLCheckResponse(**json.loads(row[0]))
                return None

        for record in _IN_MEMORY_DB:
            if record.scan_id == scan_id:
                return record
        return None


def get_statistics() -> StatsResponse:
    """Aggregate total, SAFE, SUSPICIOUS, and PHISHING counts from persistent storage."""
    client = _get_firestore_client()
    if client is not None:
        docs = client.collection(COLLECTION_NAME).select(["classification"]).stream()
        total = safe = suspicious = phishing = 0
        for doc in docs:
            data = doc.to_dict() or {}
            cls = data.get("classification")
            total += 1
            if cls == "SAFE":
                safe += 1
            elif cls == "SUSPICIOUS":
                suspicious += 1
            elif cls == "PHISHING":
                phishing += 1
        return StatsResponse(
            total_scans=total,
            safe_count=safe,
            suspicious_count=suspicious,
            phishing_count=phishing,
        )

    db_path = _get_sqlite_path()
    with _sqlite_lock:
        if db_path != ":memory:" and os.path.exists(db_path):
            with closing(sqlite3.connect(db_path)) as conn:
                _init_sqlite_table(conn)
                cursor = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN classification = 'SAFE' THEN 1 ELSE 0 END) AS safe_cnt,
                        SUM(CASE WHEN classification = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS susp_cnt,
                        SUM(CASE WHEN classification = 'PHISHING' THEN 1 ELSE 0 END) AS phish_cnt
                    FROM phishing_scans
                    """
                )
                row = cursor.fetchone()
                total = int(row[0] or 0) if row else 0
                safe = int(row[1] or 0) if row else 0
                suspicious = int(row[2] or 0) if row else 0
                phishing = int(row[3] or 0) if row else 0
                return StatsResponse(
                    total_scans=total,
                    safe_count=safe,
                    suspicious_count=suspicious,
                    phishing_count=phishing,
                )

        total = len(_IN_MEMORY_DB)
        safe = sum(1 for item in _IN_MEMORY_DB if item.classification == "SAFE")
        suspicious = sum(1 for item in _IN_MEMORY_DB if item.classification == "SUSPICIOUS")
        phishing = sum(1 for item in _IN_MEMORY_DB if item.classification == "PHISHING")
        return StatsResponse(
            total_scans=total,
            safe_count=safe,
            suspicious_count=suspicious,
            phishing_count=phishing,
        )


def clear_history() -> int:
    """Delete all stored scan records and return count deleted."""
    client = _get_firestore_client()
    if client is not None:
        deleted = 0
        batch = client.batch()
        batch_count = 0
        for doc in client.collection(COLLECTION_NAME).stream():
            batch.delete(doc.reference)
            deleted += 1
            batch_count += 1
            if batch_count >= 400:
                batch.commit()
                batch = client.batch()
                batch_count = 0
        if batch_count > 0:
            batch.commit()
        return deleted

    db_path = _get_sqlite_path()
    with _sqlite_lock:
        deleted = len(_IN_MEMORY_DB)
        _IN_MEMORY_DB.clear()
        if db_path != ":memory:" and os.path.exists(db_path):
            with closing(sqlite3.connect(db_path)) as conn:
                _init_sqlite_table(conn)
                cur = conn.execute("DELETE FROM phishing_scans")
                deleted = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else deleted
                conn.commit()
        return deleted
