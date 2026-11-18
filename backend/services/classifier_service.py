from datetime import datetime, timezone
import os
from urllib.parse import urlparse
import uuid

from Detection.classifier import evaluate_rules_and_score
from Detection.domain_checker import check_domain_and_ssl, is_unsafe_ip
from Detection.feature_extraction import extract_features, is_ip_host, split_domain_parts
from backend.schemas import DomainInfo, FeatureDetails, URLCheckResponse
from backend.services import firestore_service


def _safe_check_domain_and_ssl(url: str) -> dict:
    """
    Execute passive DNS, RDAP domain age, and SSL/TLS verification with SSRF protection.
    In production (SKIP_NETWORK_CHECKS=false), performs actual network checks and never simulates data.
    In offline test fixture mode (SKIP_NETWORK_CHECKS=true), uses deterministic test fixtures.
    """
    if os.getenv("SKIP_NETWORK_CHECKS", "false").lower() != "true":
        return check_domain_and_ssl(url)

    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower().strip(".")
    registrable_domain, _ = split_domain_parts(hostname)

    if not hostname or is_ip_host(hostname):
        return {
            "hostname": hostname or "Unknown",
            "registrable_domain": registrable_domain or "Unknown",
            "dns_resolved": False,
            "ip_address": hostname or "Unknown",
            "ssl_status": "Unavailable",
            "ssl_valid": False,
            "ssl_expiry": "Unknown",
            "domain_age_days": None,
            "domain_age_status": "unavailable",
            "registration_date": None,
            "ssrf_blocked": is_unsafe_ip(hostname) if hostname else False,
        }

    is_https = parsed.scheme.lower() == "https"
    return {
        "hostname": hostname,
        "registrable_domain": registrable_domain,
        "dns_resolved": True,
        "ip_address": "93.184.216.34",
        "ssl_status": "Valid" if is_https else "Unavailable",
        "ssl_valid": is_https,
        "ssl_expiry": "2027-12-31" if is_https else "Unknown",
        "domain_age_days": None,
        "domain_age_status": "unavailable",
        "registration_date": None,
        "ssrf_blocked": False,
    }


def analyze_url(url: str) -> URLCheckResponse:
    """
    Analyze a URL across all 10 PRD features, evaluate R-01..R-05 rules,
    and persist the result to Firestore (or persistent local database fallback).
    """
    raw_features = extract_features(url)
    raw_domain_info = _safe_check_domain_and_ssl(url)
    eval_result = evaluate_rules_and_score(raw_features, raw_domain_info)

    # Sync domain age & SSL fields into features object
    raw_features["domain_age_days"] = raw_domain_info.get("domain_age_days")
    raw_features["domain_age_status"] = raw_domain_info.get("domain_age_status", "unavailable")
    raw_features["ssl_valid"] = bool(raw_domain_info.get("ssl_valid"))
    raw_features["ssl_status"] = str(raw_domain_info.get("ssl_status", "Unavailable"))

    classification_upper = eval_result["classification"].upper()
    if classification_upper not in {"SAFE", "SUSPICIOUS", "PHISHING"}:
        classification_upper = "SUSPICIOUS"

    scan_record = URLCheckResponse(
        scan_id=f"scan-{uuid.uuid4().hex[:8]}",
        url=url,
        url_length=raw_features["url_length"],
        has_ip=bool(raw_features["has_ip"]),
        has_https=bool(raw_features["is_https"]),
        domain_age=raw_domain_info.get("domain_age_days"),
        ssl_valid=bool(raw_domain_info.get("ssl_valid")),
        classification=classification_upper,  # type: ignore[arg-type]
        risk_score=eval_result["risk_score"],
        technical_status=eval_result["technical_status"],
        classification_reason=eval_result["classification_reason"],
        scanned_at=datetime.now(timezone.utc).isoformat(),
        features=FeatureDetails(**raw_features),
        domain_info=DomainInfo(**raw_domain_info),
        rules_triggered=eval_result["rules_triggered"],
    )

    return firestore_service.save_scan(scan_record)
