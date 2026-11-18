from difflib import SequenceMatcher
import ipaddress
import os
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

# Multi-label public suffixes (ccTLD second-level hierarchies)
PUBLIC_SUFFIXES = {
    "co.id", "ac.id", "go.id", "or.id", "sch.id", "web.id", "my.id", "biz.id", "desa.id", "mil.id", "net.id",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.my", "edu.my", "gov.my", "net.my", "org.my",
    "co.nz", "org.nz", "govt.nz", "ac.nz",
    "com.br", "org.br", "gov.br", "edu.br",
    "co.in", "org.in", "gov.in", "ac.in", "net.in",
    "com.cn", "org.cn", "gov.cn", "edu.cn",
    "co.kr", "or.kr", "go.kr", "ac.kr",
    "co.za", "org.za", "gov.za", "ac.za",
}

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "credential",
    "token",
    "update",
    "signin",
    "confirm",
    "wallet",
    "password",
    "auth",
    "billing",
    "unlock",
    "suspend",
    "pay",
    "free",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "s.id",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "tiny.cc",
    "rb.gy",
    "lnkd.in",
    "linktr.ee",
}

DEFAULT_PROTECTED_DOMAINS = [
    "google.com",
    "bca.co.id",
    "klikbca.com",
    "bankmandiri.co.id",
    "bri.co.id",
    "bni.co.id",
    "bsi.co.id",
    "btn.co.id",
    "cimbniaga.co.id",
    "danamon.co.id",
    "permata.co.id",
    "tokopedia.com",
    "shopee.co.id",
    "bukalapak.com",
    "blibli.com",
    "traveloka.com",
    "tiket.com",
    "gojek.com",
    "grab.com",
    "dana.id",
    "ovo.id",
    "linkaja.id",
    "gopay.co.id",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "icloud.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "netflix.com",
    "amazon.com",
    "binance.com",
    "indodax.com",
    "pajak.go.id",
    "bpjs-kesehatan.go.id",
]


def get_protected_domains() -> List[str]:
    """Return configurable list of official domains for domain similarity detection."""
    extra_raw = os.getenv("PROTECTED_DOMAINS", "").strip()
    domains = list(DEFAULT_PROTECTED_DOMAINS)
    if extra_raw:
        for item in extra_raw.split(","):
            cleaned = item.strip().lower()
            if cleaned and cleaned not in domains:
                domains.append(cleaned)
    return domains


def is_ip_host(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 literal."""
    if not hostname:
        return False
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", clean))


def split_domain_parts(hostname: str) -> Tuple[str, int]:
    """
    Split a hostname into (registrable_domain, subdomain_count)
    with multi-label public suffix awareness.
    """
    clean_host = (hostname or "").lower().strip(".")
    if not clean_host or is_ip_host(clean_host):
        return clean_host, 0

    labels = clean_host.split(".")
    if len(labels) < 2:
        return clean_host, 0

    last_two = f"{labels[-2]}.{labels[-1]}"
    if last_two in PUBLIC_SUFFIXES and len(labels) >= 3:
        registrable = f"{labels[-3]}.{last_two}"
        sub_count = max(0, len(labels) - 3)
    else:
        registrable = last_two
        sub_count = max(0, len(labels) - 2)

    return registrable, sub_count


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(text: str, one_as: str = "l") -> str:
    """Normalize common leetspeak and visual homoglyphs used in typosquatting."""
    out = text.lower()
    out = out.replace("rn", "m").replace("vv", "w")
    trans = {
        "0": "o",
        "1": one_as,
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
    return "".join(trans.get(ch, ch) for ch in out)


def detect_domain_similarity(hostname: str, registrable_domain: str) -> Tuple[bool, Optional[str], float]:
    """
    Detect if hostname/registrable_domain imitates an official protected domain
    via typosquatting, homoglyphs/leetspeak, or deceptive brand combosquatting.
    """
    clean_host = (hostname or "").lower().strip(".")
    reg_dom = (registrable_domain or "").lower().strip(".")
    if not clean_host or not reg_dom or is_ip_host(clean_host):
        return False, None, 0.0

    protected = get_protected_domains()
    protected_set = set(protected)

    # Exact match with an official domain (or legitimate subdomain of it) is NOT typosquatting
    if reg_dom in protected_set:
        return False, None, 0.0

    target_sld = reg_dom.split(".")[0]
    target_sld_no_hyphen = target_sld.replace("-", "")
    norm_l = _normalize_homoglyphs(target_sld_no_hyphen, one_as="l")
    norm_i = _normalize_homoglyphs(target_sld_no_hyphen, one_as="i")

    host_tokens = set(re.split(r"[.\-_]+", clean_host))

    best_match: Optional[str] = None
    best_score: float = 0.0

    for official in protected:
        official_sld = official.split(".")[0]
        official_clean = official_sld.replace("-", "")

        # 1. Homoglyph / leetspeak / hyphenation spoofing (e.g., g00gle.com, kl1kbca.com, bank-mandiri.com)
        if len(official_clean) >= 4 and (norm_l == official_clean or norm_i == official_clean):
            return True, official, 0.95

        # 2. 1-character typo / edit distance on brand name (length >= 5)
        if len(official_clean) >= 5:
            dist = min(
                _levenshtein(target_sld, official_sld),
                _levenshtein(norm_l, official_clean),
                _levenshtein(norm_i, official_clean),
            )
            if dist == 1:
                ratio = SequenceMatcher(None, target_sld, official_sld).ratio()
                score = round(max(ratio, 0.88), 2)
                if score > best_score:
                    best_score = score
                    best_match = official

        # 3. Brand combosquatting in domain or subdomain (e.g. klikbca-login.com, bca.verify-account.com)
        if len(official_clean) >= 3 and official_clean in host_tokens:
            score = 0.85
            if score > best_score:
                best_score = score
                best_match = official

    if best_match is not None:
        return True, best_match, best_score

    return False, None, 0.0


def extract_features(url: str) -> dict:
    """Extract all 10 PRD URL & lexical detection features."""
    raw_url = (url or "").strip()
    parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    hostname = (parsed.hostname or "").lower().strip(".")
    url_lower = raw_url.lower()

    # 1. URL Length
    url_length = len(raw_url)
    is_long_url = url_length > 75

    # 2. IP Address (IPv4 or IPv6)
    has_ip = 1 if is_ip_host(hostname) else 0

    # 3. Special Characters (@, -, %, _, ?, =, &)
    has_at = 1 if "@" in raw_url else 0
    hyphen_count = hostname.count("-")
    percent_count = raw_url.count("%")
    special_char_count = sum(raw_url.count(ch) for ch in ("@", "-", "%", "_", "?", "=", "&"))

    # 4. Subdomain (Public Suffix aware)
    registrable_domain, subdomain_count = split_domain_parts(hostname)

    # 5. HTTPS Protocol
    is_https = 1 if parsed.scheme.lower() == "https" else 0
    has_https = bool(is_https)

    # 7. Suspicious Keywords (checked in URL path/host/query)
    suspicious_keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    # 8. URL Shortening Service
    is_shortened = (hostname in SHORTENER_DOMAINS) or (registrable_domain in SHORTENER_DOMAINS)

    # 9. Domain Similarity / Typosquatting
    similarity_detected, similar_to_domain, similarity_score = detect_domain_similarity(
        hostname, registrable_domain
    )

    return {
        "url_length": url_length,
        "is_long_url": is_long_url,
        "has_ip": has_ip,
        "has_at": has_at,
        "hyphen_count": hyphen_count,
        "percent_count": percent_count,
        "special_char_count": special_char_count,
        "subdomain_count": subdomain_count,
        "registrable_domain": registrable_domain,
        "is_https": is_https,
        "has_https": has_https,
        "suspicious_keywords_found": suspicious_keywords_found,
        "is_shortened": is_shortened,
        "similarity_detected": similarity_detected,
        "similar_to_domain": similar_to_domain,
        "similarity_score": similarity_score,
    }
