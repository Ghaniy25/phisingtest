try:
    from Detection.feature_extraction import extract_features
    from Detection.domain_checker import check_domain_and_ssl
except ImportError:
    from feature_extraction import extract_features
    from domain_checker import check_domain_and_ssl

def classify_url(url: str) -> dict:
    features = extract_features(url)
    domain_info = check_domain_and_ssl(url)

    risk_score = 0

    # Pembobotan skor risiko berdasarkan fitur leksikal URL
    if features["has_ip"] == 1:
        risk_score += 40
    if features["has_at"] == 1:
        risk_score += 30
    if features["url_length"] > 75:
        risk_score += 20
    elif features["url_length"] > 54:
        risk_score += 10
    if features["hyphen_count"] >= 3:
        risk_score += 20
    elif features["hyphen_count"] >= 1:
        risk_score += 5
    if features["subdomain_count"] >= 3:
        risk_score += 20
    elif features["subdomain_count"] == 2:
        risk_score += 10
    if features["is_https"] == 0:
        risk_score += 10

    # Pembobotan tambahan dari hasil pemeriksaan DNS & SSL pasif
    if not domain_info["dns_resolved"]:
        risk_score += 15
    if domain_info["ssl_status"] in ["Invalid / Self-Signed", "Expired"]:
        risk_score += 25

    risk_score = min(100, risk_score)

    # Penentuan kategori akhir
    if risk_score >= 60:
        classification = "Phishing"
    elif risk_score >= 30:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return {
        "url": url,
        "classification": classification,
        "risk_score": risk_score,
        "features": features,
        "domain_info": domain_info
    }

if __name__ == "__main__":
    contoh_url = [
        "https://www.google.com",
        "http://192.168.1.50/login-bca@verify.com",
        "http://update-akun.login.verify.contoh-domain.com"
    ]
    for u in contoh_url:
        print(classify_url(u))
        print("-" * 60)