import re
from urllib.parse import urlparse

def extract_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""

    # 1. Panjang total URL
    url_length = len(url)

    # 2. Keberadaan karakter '@'
    has_at = 1 if "@" in url else 0

    # 3. Jumlah tanda hubung '-' pada hostname
    hyphen_count = hostname.count("-")

    # 4. Jumlah subdomain
    dot_count = hostname.count(".")
    subdomain_count = max(0, dot_count - 1)

    # 5. Penggunaan alamat IPv4 sebagai hostname
    ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    has_ip = 1 if re.match(ip_regex, hostname) else 0

    # 6. Status protokol HTTPS
    is_https = 1 if parsed.scheme == "https" else 0

    return {
        "url_length": url_length,
        "has_at": has_at,
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_count,
        "has_ip": has_ip,
        "is_https": is_https
    }