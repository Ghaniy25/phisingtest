import ipaddress
import re
from typing import List, Literal, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator

DANGEROUS_SCHEMES = ("javascript:", "data:", "file:", "vbscript:", "mailto:", "ftp:")
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}
HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_domain(hostname: str) -> bool:
    """Validate domain syntax (at least two labels, valid characters, valid TLD)."""
    clean_host = hostname.rstrip(".")
    if "." not in clean_host or len(clean_host) > 253:
        return False
    labels = clean_host.split(".")
    if any(not HOSTNAME_LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    if tld.isdigit() or len(tld) < 2:
        return False
    return True


class URLCheckRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="Target URL to be analyzed for phishing indicators",
    )

    @field_validator("url")
    @classmethod
    def validate_and_normalize_url(cls, value: str) -> str:
        url = value.strip()
        if not url:
            raise ValueError("URL tidak boleh kosong.")
        if len(url) < 4:
            raise ValueError("URL terlalu pendek (minimal 4 karakter).")
        if len(url) > 2048:
            raise ValueError("URL terlalu panjang (maksimal 2048 karakter).")
        if any(ch.isspace() for ch in url):
            raise ValueError("URL tidak boleh mengandung spasi atau karakter whitespace.")

        lower_url = url.lower()
        if lower_url.startswith(DANGEROUS_SCHEMES):
            raise ValueError("Skema URL tidak diizinkan demi keamanan.")

        if "://" in url:
            scheme, rest = url.split("://", 1)
            scheme_lower = scheme.lower()
            if scheme_lower not in {"http", "https"}:
                raise ValueError("Hanya protokol http:// dan https:// yang didukung.")
            normalized_url = f"{scheme_lower}://{rest}"
        else:
            normalized_url = f"http://{url}"

        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            raise ValueError("Format URL tidak valid: hostname tidak ditemukan.")

        if hostname in BLOCKED_HOSTNAMES or hostname.endswith((".local", ".internal")):
            raise ValueError("Target hostname lokal atau metadata internal diblokir (proteksi SSRF).")

        # Check IP address (IPv4 or IPv6) vs Domain name
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
                or ip_obj.is_multicast
            ):
                raise ValueError("Alamat IP loopback, link-local, atau metadata cloud diblokir (proteksi SSRF).")
        except ValueError as exc:
            if "proteksi SSRF" in str(exc):
                raise
            if not _is_valid_domain(hostname):
                raise ValueError("Format domain pada URL tidak valid.")

        return normalized_url


class FeatureDetails(BaseModel):
    # 1. URL Length
    url_length: int = Field(..., ge=0, description="Total character count of the URL")
    is_long_url: bool = Field(default=False, description="True if URL length exceeds 75 chars")
    # 2. IP Address (IPv4 / IPv6)
    has_ip: int = Field(..., ge=0, le=1, description="1 if IPv4/IPv6 address is used as host, else 0")
    # 3. Special Characters
    has_at: int = Field(..., ge=0, le=1, description="1 if '@' character is present in URL, else 0")
    hyphen_count: int = Field(..., ge=0, description="Count of '-' characters in hostname")
    percent_count: int = Field(default=0, ge=0, description="Count of '%' percent-encoding chars in URL")
    special_char_count: int = Field(default=0, ge=0, description="Total relevant special characters (@, -, %, _, ?, =, &)")
    # 4. Subdomain (Public Suffix aware)
    subdomain_count: int = Field(..., ge=0, description="Number of subdomain levels excluding public suffix")
    registrable_domain: str = Field(default="", description="Extracted registrable base domain")
    # 5. HTTPS
    is_https: int = Field(..., ge=0, le=1, description="1 if HTTPS protocol is used, else 0")
    has_https: bool = Field(default=False, description="Boolean flag for HTTPS usage")
    # 6. Domain Age (RDAP)
    domain_age_days: Optional[int] = Field(default=None, description="Actual domain age in days from RDAP, or null if unavailable")
    domain_age_status: Literal["available", "unavailable", "error"] = Field(
        default="unavailable", description="Status of domain age lookup"
    )
    # 7. Suspicious Keywords
    suspicious_keywords_found: List[str] = Field(
        default_factory=list, description="List of suspicious keywords detected in the URL"
    )
    # 8. URL Shortening
    is_shortened: bool = Field(default=False, description="True if hostname belongs to a known URL shortener service")
    # 9. Domain Similarity
    similarity_detected: bool = Field(
        default=False, description="True if hostname resembles an official protected domain with altered spelling"
    )
    similar_to_domain: Optional[str] = Field(
        default=None, description="Official protected domain that this hostname resembles"
    )
    similarity_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Normalized similarity score (0.0 - 1.0)"
    )
    # 10. SSL Certificate
    ssl_valid: bool = Field(default=False, description="True only if active SSL certificate was verified as valid")
    ssl_status: str = Field(
        default="unavailable",
        description="SSL status: valid, invalid, expired, unavailable, or error",
    )


class DomainInfo(BaseModel):
    hostname: str = Field(..., description="Extracted domain hostname")
    registrable_domain: str = Field(default="", description="Base registrable domain")
    dns_resolved: bool = Field(..., description="True if DNS resolution succeeded to a safe public IP")
    ip_address: str = Field(..., description="Resolved IP address or Unknown")
    ssl_status: str = Field(..., description="SSL certificate status (Valid, Invalid / Self-Signed, Expired, Unavailable, Error)")
    ssl_valid: bool = Field(default=False, description="True if SSL certificate is valid")
    ssl_expiry: str = Field(..., description="SSL certificate expiry date (YYYY-MM-DD) or Unknown")
    domain_age_days: Optional[int] = Field(default=None, description="Domain age in days from RDAP or null")
    domain_age_status: Literal["available", "unavailable", "error"] = Field(
        default="unavailable", description="RDAP domain age availability status"
    )
    registration_date: Optional[str] = Field(default=None, description="ISO registration date from RDAP if available")
    ssrf_blocked: bool = Field(default=False, description="True if outbound connection was blocked by SSRF protection")


class URLCheckResponse(BaseModel):
    scan_id: str = Field(..., description="Unique identifier for this scan session")
    url: str = Field(..., description="The analyzed URL")
    url_length: int = Field(..., ge=0, description="Top-level URL character length")
    has_ip: bool = Field(..., description="Top-level boolean flag for IP host usage")
    has_https: bool = Field(..., description="Top-level boolean flag for HTTPS protocol")
    domain_age: Optional[int] = Field(default=None, description="Top-level domain age in days (null if unavailable)")
    ssl_valid: bool = Field(..., description="Top-level boolean flag for SSL certificate validity")
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING"] = Field(..., description="Threat classification status")
    risk_score: int = Field(..., ge=0, le=100, description="Rule-based risk score between 0 and 100")
    technical_status: Literal["complete", "inconclusive"] = Field(
        default="complete",
        description="Whether technical verification (DNS, SSL, RDAP) succeeded completely or was inconclusive",
    )
    classification_reason: str = Field(
        default="", description="Clear human-readable explanation of why this classification was assigned"
    )
    scanned_at: str = Field(..., description="ISO 8601 formatted scan timestamp")
    features: FeatureDetails = Field(..., description="All 10 extracted phishing detection features")
    domain_info: DomainInfo = Field(..., description="Passive DNS, RDAP domain age, and SSL certificate analysis")
    rules_triggered: List[str] = Field(default_factory=list, description="List of PRD rules (R-01..R-05) triggered")


class HistoryItem(BaseModel):
    scan_id: str
    url: str
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    risk_score: int
    scanned_at: str


class StatsResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
