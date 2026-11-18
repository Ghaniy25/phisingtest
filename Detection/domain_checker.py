from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
import ssl
from typing import Optional, Tuple
import urllib.error
import urllib.request
from urllib.parse import urlparse

try:
    from Detection.feature_extraction import is_ip_host, split_domain_parts
except ImportError:
    from feature_extraction import is_ip_host, split_domain_parts

MAX_RDAP_BYTES = 65536
NETWORK_TIMEOUT_SECONDS = 3.0
BLOCKED_INTERNAL_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal"}


def is_unsafe_ip(ip_str: str) -> bool:
    """Return True if IP address is private, loopback, link-local, multicast, reserved, or unspecified."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip("[]"))
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True


def fetch_domain_age_rdap(
    registrable_domain: str, timeout: float = NETWORK_TIMEOUT_SECONDS
) -> Tuple[Optional[int], str, Optional[str]]:
    """
    Query public RDAP for actual domain registration date and calculate domain age in days.
    Returns (domain_age_days, domain_age_status, registration_date_yyyy_mm_dd).
    Never simulates or invents domain age values.
    """
    if not registrable_domain or is_ip_host(registrable_domain):
        return None, "unavailable", None

    if os.getenv("SKIP_NETWORK_CHECKS", "false").lower() == "true":
        return None, "unavailable", None

    rdap_url = f"https://rdap.org/domain/{registrable_domain}"
    req = urllib.request.Request(
        rdap_url,
        headers={"Accept": "application/rdap+json, application/json", "User-Agent": "SmartPhishingDetector/2.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read(MAX_RDAP_BYTES)
            payload = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError:
        return None, "unavailable", None
    except Exception:
        return None, "unavailable", None

    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        return None, "unavailable", None

    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        date_str = event.get("eventDate")
        if action in {"registration", "registered"} and isinstance(date_str, str):
            try:
                normalized = date_str.strip().replace("Z", "+00:00")
                reg_dt = datetime.fromisoformat(normalized)
                if reg_dt.tzinfo is None:
                    reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
                age_days = max(0, (now_utc - reg_dt).days)
                return age_days, "available", reg_dt.strftime("%Y-%m-%d")
            except ValueError:
                continue

    return None, "unavailable", None


def check_domain_and_ssl(url: str) -> dict:
    """
    Perform passive DNS resolution (with DNS-rebinding SSRF verification),
    actual RDAP domain age query, and actual SSL/TLS certificate verification.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower().strip(".")
    registrable_domain, _ = split_domain_parts(hostname)

    result = {
        "hostname": hostname or "Unknown",
        "registrable_domain": registrable_domain or "Unknown",
        "dns_resolved": False,
        "ip_address": "Unknown",
        "ssl_status": "Unavailable",
        "ssl_valid": False,
        "ssl_expiry": "Unknown",
        "domain_age_days": None,
        "domain_age_status": "unavailable",
        "registration_date": None,
        "ssrf_blocked": False,
    }

    if not hostname:
        return result

    # 1. Anti-SSRF check on hostname or literal IP before any network activity
    if hostname in BLOCKED_INTERNAL_HOSTS or hostname.endswith((".local", ".internal")):
        result["ssrf_blocked"] = True
        return result

    if is_ip_host(hostname):
        result["ip_address"] = hostname
        if is_unsafe_ip(hostname):
            result["ssrf_blocked"] = True
            return result

    if os.getenv("SKIP_NETWORK_CHECKS", "false").lower() == "true":
        return result

    # 2. Passive DNS Resolution + DNS Rebinding Verification
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        resolved_ips = []
        for info in addr_infos:
            sockaddr = info[4]
            if sockaddr and isinstance(sockaddr[0], str):
                resolved_ips.append(sockaddr[0])
        if not resolved_ips:
            return result

        # Block if ANY resolved IP points to internal/private/loopback/metadata space (DNS Rebinding protection)
        if any(is_unsafe_ip(ip) for ip in resolved_ips):
            result["ssrf_blocked"] = True
            result["dns_resolved"] = False
            result["ip_address"] = "Blocked-Internal-IP"
            return result

        result["dns_resolved"] = True
        result["ip_address"] = resolved_ips[0]
    except Exception:
        result["dns_resolved"] = False
        return result

    # 3. Actual RDAP Domain Age Lookup (only for public domain names)
    age_days, age_status, reg_date = fetch_domain_age_rdap(registrable_domain)
    result["domain_age_days"] = age_days
    result["domain_age_status"] = age_status
    result["registration_date"] = reg_date

    # 4. Actual Passive SSL/TLS Certificate Check on Port 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=NETWORK_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if isinstance(cert, dict):
                    not_after = cert.get("notAfter")
                    if isinstance(not_after, str):
                        expiry_dt = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        result["ssl_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                        if expiry_dt > datetime.now(timezone.utc):
                            result["ssl_status"] = "Valid"
                            result["ssl_valid"] = True
                        else:
                            result["ssl_status"] = "Expired"
                            result["ssl_valid"] = False
                    else:
                        result["ssl_status"] = "Valid"
                        result["ssl_valid"] = True
                else:
                    result["ssl_status"] = "Unavailable"
                    result["ssl_valid"] = False
    except ssl.SSLCertVerificationError:
        result["ssl_status"] = "Invalid / Self-Signed"
        result["ssl_valid"] = False
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["ssl_status"] = "Unavailable"
        result["ssl_valid"] = False
    except Exception:
        result["ssl_status"] = "Error"
        result["ssl_valid"] = False

    return result
