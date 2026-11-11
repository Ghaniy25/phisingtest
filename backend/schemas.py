from typing import List, Literal
from pydantic import BaseModel, Field


class URLCheckRequest(BaseModel):
    url: str = Field(..., description="Target URL to be analyzed for phishing indicators")


class FeatureDetails(BaseModel):
    url_length: int = Field(..., description="Total character count of the URL")
    has_ip: bool = Field(..., description="True if an IP address is directly used instead of a hostname")
    has_https: bool = Field(..., description="True if HTTPS protocol is used")
    subdomain_count: int = Field(..., description="Number of subdomain levels in the domain")
    suspicious_keywords_found: List[str] = Field(default_factory=list, description="Suspicious keywords identified in URL")
    is_shortened: bool = Field(..., description="True if URL uses a known link shortening service")
    domain_age_days: int = Field(..., description="Estimated domain age in days")
    ssl_valid: bool = Field(..., description="True if SSL certificate is valid")


class URLCheckResponse(BaseModel):
    scan_id: str = Field(..., description="Unique identifier for this scan session")
    url: str = Field(..., description="The analyzed URL")
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING"] = Field(..., description="Threat classification status")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated risk score between 0 and 100")
    scanned_at: str = Field(..., description="ISO 8601 formatted scan timestamp")
    features: FeatureDetails = Field(..., description="Extracted structural and heuristic features")
    rules_triggered: List[str] = Field(default_factory=list, description="List of rule IDs and explanations triggered")


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

