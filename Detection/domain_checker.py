import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_domain_and_ssl(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname

    result = {
        "hostname": hostname or "Unknown",
        "dns_resolved": False,
        "ip_address": "Unknown",
        "ssl_status": "Unknown",
        "ssl_expiry": "Unknown"
    }

    if not hostname:
        return result

    # 1. Cek resolusi DNS secara pasif
    try:
        ip_address = socket.gethostbyname(hostname)
        result["dns_resolved"] = True
        result["ip_address"] = ip_address
    except Exception:
        result["dns_resolved"] = False
        return result

    # 2. Cek masa berlaku sertifikat SSL/TLS secara pasif tanpa membuka halaman web
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if isinstance(cert, dict):
                    not_after = cert.get("notAfter")
                    if isinstance(not_after, str):
                        expiry_dt = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        result["ssl_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                        result["ssl_status"] = (
                            "Valid" if expiry_dt > datetime.now(timezone.utc) else "Expired"
                        )
                    else:
                        result["ssl_status"] = "Valid"
                else:
                    result["ssl_status"] = "Unknown"
    except ssl.SSLCertVerificationError:
        result["ssl_status"] = "Invalid / Self-Signed"
    except Exception:
        result["ssl_status"] = "Unknown"

    return result