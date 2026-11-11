import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List

from backend.schemas import FeatureDetails, URLCheckResponse

# In-memory storage for scan history
MOCK_HISTORY_DB: List[URLCheckResponse] = []

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "bank",
    "update",
    "secure",
    "pay",
    "signin",
    "free",
    "token",
    "wallet",
    "credential",
    "authenticate",
    "confirm",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "shorturl.at",
}

# Regex to detect IPv4 address format in host or URL
IP_REGEX = re.compile(
    r"(?:^|https?://|//)"
    r"((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?::\d{1,5})?(?:/|$)"
)


def extract_features(raw_url: str) -> FeatureDetails:
    """Extract structural and heuristic features from the URL."""
    url = raw_url.strip()
    url_lower = url.lower()

    # Prepend scheme if missing for proper urllib parsing
    parse_target = url if ("://" in url) else f"http://{url}"
    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower()

    # Feature 1: URL Length
    url_length = len(url)

    # Feature 2: Has IP Address
    has_ip = bool(IP_REGEX.search(url) or re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))

    # Feature 3: Has HTTPS
    has_https = url_lower.startswith("https://")

    # Feature 4: Subdomain Count
    subdomain_count = 0
    if hostname and not has_ip:
        host_parts = hostname.split(".")
        if len(host_parts) > 2:
            subdomain_count = len(host_parts) - 2

    # Feature 5: Suspicious Keywords Found
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    # Feature 6: Is Shortened URL
    is_shortened = hostname in SHORTENER_DOMAINS

    # Feature 7 & 8: Domain Age and SSL Validity (Mocked realistically)
    if has_ip or len(keywords_found) >= 2 or "@" in url:
        domain_age_days = 7
        ssl_valid = False
    elif not has_https or len(keywords_found) == 1 or url_length > 75:
        domain_age_days = 45
        ssl_valid = has_https
    else:
        domain_age_days = 730
        ssl_valid = True

    return FeatureDetails(
        url_length=url_length,
        has_ip=has_ip,
        has_https=has_https,
        subdomain_count=subdomain_count,
        suspicious_keywords_found=keywords_found,
        is_shortened=is_shortened,
        domain_age_days=domain_age_days,
        ssl_valid=ssl_valid,
    )


def analyze_url(url: str) -> URLCheckResponse:
    """Analyze a URL and classify its phishing risk score."""
    features = extract_features(url)
    keyword_count = len(features.suspicious_keywords_found)
    has_at_symbol = "@" in url

    # Rule evaluation and classification logic
    if features.has_ip or keyword_count >= 2 or has_at_symbol:
        classification = "PHISHING"
        base_score = 80 + min(keyword_count * 5, 15)
        if features.has_ip:
            base_score += 3
        if has_at_symbol:
            base_score += 4
        risk_score = min(max(base_score, 80), 98)
        rules_triggered = [
            "R-01: Direct IP address or high-risk keywords used",
            "R-03: Multiple domain anomalies detected",
        ]
        if has_at_symbol:
            rules_triggered.append("R-08: Credential obfuscation '@' detected in URL")
        if features.is_shortened:
            rules_triggered.append("R-04: Suspicious link shortening service detected")
        if not features.has_https:
            rules_triggered.append("R-06: Non-secure transmission protocol (HTTP)")

    elif keyword_count == 1 or features.url_length > 75 or not features.has_https:
        classification = "SUSPICIOUS"
        base_score = 45
        if keyword_count == 1:
            base_score += 15
        if features.url_length > 75:
            base_score += 10
        if not features.has_https:
            base_score += 5
        risk_score = min(max(base_score, 45), 75)
        rules_triggered = ["R-02: Suspicious URL patterns or missing HTTPS"]
        if features.url_length > 75:
            rules_triggered.append("R-07: Excessive URL character length (>75 chars)")

    else:
        classification = "SAFE"
        risk_score = 5 + min(features.subdomain_count * 4, 15)
        rules_triggered = ["R-05: Standard legitimate URL features"]

    scan_record = URLCheckResponse(
        scan_id=f"scan-{uuid.uuid4().hex[:8]}",
        url=url,
        classification=classification,
        risk_score=risk_score,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        features=features,
        rules_triggered=rules_triggered,
    )

    # Persist in memory database (newest scans at beginning of list)
    MOCK_HISTORY_DB.insert(0, scan_record)
    return scan_record


def clear_history_database() -> int:
    """Clear all records from in-memory history DB."""
    count = len(MOCK_HISTORY_DB)
    MOCK_HISTORY_DB.clear()
    return count


def reset_history_database() -> int:
    """Reset the database to seeded demonstration records."""
    MOCK_HISTORY_DB.clear()
    sample_urls = [
        "https://www.google.com",
        "http://secure-account-verification-login-service.net/bank-update?token=xyz99823487293847923847923847293847293847",
        "http://192.168.1.105/login.php?user=admin",
        "http://contoh-aplikasi-phishing.com/verify",
        "https://github.com/explore",
    ]
    for sample in reversed(sample_urls):
        analyze_url(sample)
    return len(MOCK_HISTORY_DB)


# Initialize DB with seed records
reset_history_database()
