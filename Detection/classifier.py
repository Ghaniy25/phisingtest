try:
    from Detection.domain_checker import check_domain_and_ssl
    from Detection.feature_extraction import extract_features
except ImportError:
    from domain_checker import check_domain_and_ssl
    from feature_extraction import extract_features


def evaluate_rules_and_score(features: dict, domain_info: dict) -> dict:
    """
    Evaluate all 10 PRD features and domain/SSL analysis using the 5 PRD rules (R-01..R-05).
    Returns dict with classification, risk_score, rules_triggered, technical_status, and classification_reason.
    """
    risk_score = 0
    suspicious_details = []
    rules_triggered = []

    # 1. URL Length
    if features["url_length"] > 75:
        risk_score += 20
        suspicious_details.append(f"panjang URL berlebihan ({features['url_length']} karakter)")
    elif features["url_length"] > 54:
        risk_score += 10
        suspicious_details.append(f"panjang URL cukup panjang ({features['url_length']} karakter)")

    # 2. IP Address
    if features["has_ip"] == 1:
        risk_score += 40
        suspicious_details.append("penggunaan alamat IP langsung sebagai host")

    # 3. Special Characters (@, -, %)
    if features["has_at"] == 1:
        risk_score += 30
        suspicious_details.append("karakter '@' pada URL")

    if features["hyphen_count"] >= 3:
        risk_score += 20
        suspicious_details.append(f"tanda hubung '-' berlebihan ({features['hyphen_count']})")
    elif features["hyphen_count"] >= 1:
        risk_score += 5
        suspicious_details.append(f"terdapat tanda hubung '-' ({features['hyphen_count']})")

    if features.get("percent_count", 0) >= 3:
        risk_score += 10
        suspicious_details.append(f"encoding '%' berulang ({features['percent_count']})")

    # 4. Subdomain Count (Public Suffix aware)
    if features["subdomain_count"] >= 3:
        risk_score += 20
        suspicious_details.append(f"banyak subdomain ({features['subdomain_count']} level)")
    elif features["subdomain_count"] == 2:
        risk_score += 10
        suspicious_details.append("menggunakan 2 level subdomain")

    # 5. HTTPS Protocol
    if features["is_https"] == 0:
        risk_score += 10
        suspicious_details.append("tidak menggunakan protokol HTTPS")

    # 6. Domain Age (RDAP)
    domain_age = domain_info.get("domain_age_days")
    domain_age_status = domain_info.get("domain_age_status", "unavailable")
    if isinstance(domain_age, int):
        if domain_age < 30:
            risk_score += 25
            suspicious_details.append(f"domain sangat baru ({domain_age} hari)")
        elif domain_age < 90:
            risk_score += 15
            suspicious_details.append(f"domain berusia muda ({domain_age} hari)")

    # 7. Suspicious Keywords
    keywords = features.get("suspicious_keywords_found", [])
    if len(keywords) >= 4:
        risk_score += 25
        suspicious_details.append(f"banyak kata kunci mencurigakan ({', '.join(keywords)})")
    elif len(keywords) >= 2:
        risk_score += 15
        suspicious_details.append(f"kata kunci mencurigakan ({', '.join(keywords)})")
    elif len(keywords) == 1:
        risk_score += 5
        suspicious_details.append(f"kata kunci '{keywords[0]}'")

    # 8. URL Shortening
    if features.get("is_shortened"):
        risk_score += 30
        suspicious_details.append("menggunakan layanan pemendek URL (URL shortener)")

    # 9. Domain Similarity (Typosquatting)
    similarity_detected = bool(features.get("similarity_detected"))
    similar_to = features.get("similar_to_domain")
    if similarity_detected:
        risk_score += 75
        suspicious_details.append(f"kemiripan domain dengan '{similar_to}'")

    # 10. Passive DNS & SSL Certificate
    dns_resolved = bool(domain_info.get("dns_resolved"))
    ssl_status = str(domain_info.get("ssl_status", "Unavailable"))
    ssl_valid = bool(domain_info.get("ssl_valid")) or (ssl_status == "Valid")

    if not dns_resolved:
        risk_score += 15
        suspicious_details.append("domain gagal diresolusi oleh DNS")

    if ssl_status in ("Invalid / Self-Signed", "Expired", "invalid", "expired"):
        risk_score += 30
        suspicious_details.append(f"sertifikat SSL tidak valid ({ssl_status})")

    # Technical verification status check
    if dns_resolved and ssl_valid and domain_age_status == "available":
        technical_status = "complete"
    else:
        technical_status = "inconclusive"

    # Evaluate the 5 Core PRD Rules (R-01 .. R-05)
    has_suspicious_chars_or_kw = (
        features["has_at"] == 1
        or features["hyphen_count"] >= 1
        or features.get("percent_count", 0) >= 1
        or len(keywords) >= 1
        or features["url_length"] > 54
    )

    # R-01: IP Address + suspicious characters/patterns -> PHISHING
    if features["has_ip"] == 1 and has_suspicious_chars_or_kw:
        risk_score = max(risk_score, 80)
        rules_triggered.append(
            "R-01: URL menggunakan IP Address dan memiliki karakter/pola mencurigakan"
        )

    # R-02: New domain + multiple subdomains -> SUSPICIOUS
    if isinstance(domain_age, int) and domain_age < 90 and features["subdomain_count"] >= 2:
        risk_score = max(risk_score, 45)
        rules_triggered.append(
            f"R-02: Domain baru ({domain_age} hari) dan memiliki banyak subdomain ({features['subdomain_count']} level)"
        )

    # R-03: Domain similarity with official domain using altered spelling -> PHISHING
    if similarity_detected:
        risk_score = max(risk_score, 80)
        rules_triggered.append(
            f"R-03: Domain memiliki kemiripan dengan domain resmi '{similar_to}' tetapi menggunakan ejaan berbeda"
        )

    # Ensure unresolved DNS or explicitly invalid/expired SSL is never classified as SAFE
    if not dns_resolved or ssl_status in ("Invalid / Self-Signed", "Expired", "invalid", "expired"):
        risk_score = max(risk_score, 30)

    risk_score = min(100, risk_score)

    # Determine final classification & R-04 / R-05
    if any(r.startswith(("R-01", "R-03")) for r in rules_triggered) or risk_score >= 60:
        classification = "Phishing"
        if not rules_triggered:
            detail_str = ", ".join(suspicious_details) if suspicious_details else "akumulasi indikator risiko tinggi"
            rules_triggered.append(
                f"R-04: Akumulasi karakteristik berisiko tinggi melampaui ambang phishing ({detail_str})"
            )
        elif suspicious_details:
            rules_triggered.append(
                f"R-04: Indikator pendukung terdeteksi ({', '.join(suspicious_details)})"
            )
    elif risk_score >= 30 or any(r.startswith("R-02") for r in rules_triggered):
        classification = "Suspicious"
        detail_str = ", ".join(suspicious_details) if suspicious_details else "pemeriksaan teknis belum lengkap"
        rules_triggered.append(
            f"R-04: URL memiliki karakteristik mencurigakan tetapi belum memenuhi aturan phishing ({detail_str})"
        )
    else:
        classification = "Safe"
        rules_triggered.append(
            "R-05: URL tidak memenuhi aturan berbahaya dan pemeriksaan teknis berhasil"
        )

    # Build transparent classification_reason
    if classification == "Phishing":
        reason = f"Terindikasi PHISHING (skor risiko {risk_score}/100) karena: " + "; ".join(suspicious_details) + "."
    elif classification == "Suspicious":
        reason = f"Terindikasi MENCURIGAKAN (skor risiko {risk_score}/100) karena: " + "; ".join(suspicious_details) + "."
        if technical_status == "inconclusive":
            reason += " Pemeriksaan teknis berstatus inconclusive (data domain/SSL tidak lengkap atau tidak valid)."
    else:
        if ssl_valid:
            reason = (
                f"Dinyatakan AMAN (skor risiko {risk_score}/100): tidak ditemukan pola berbahaya, "
                "resolusi DNS berhasil, dan sertifikat SSL/TLS valid."
            )
            if domain_age_status != "available":
                reason += " (Catatan: data usia domain RDAP tidak tersedia/inconclusive, namun DNS dan SSL valid)."
        else:
            reason = (
                f"Dinyatakan AMAN secara struktur & DNS (skor risiko {risk_score}/100): tidak ditemukan pola berbahaya "
                "dan resolusi DNS berhasil. (Catatan: pemeriksaan aktif port 443 SSL/RDAP dibatasi jaringan/unavailable)."
            )

    return {
        "classification": classification,
        "risk_score": risk_score,
        "rules_triggered": rules_triggered,
        "technical_status": technical_status,
        "classification_reason": reason,
    }


def classify_url(url: str) -> dict:
    features = extract_features(url)
    domain_info = check_domain_and_ssl(url)
    eval_result = evaluate_rules_and_score(features, domain_info)

    # Sync domain age and SSL fields into features dict for complete 10-feature visibility
    features["domain_age_days"] = domain_info.get("domain_age_days")
    features["domain_age_status"] = domain_info.get("domain_age_status", "unavailable")
    features["ssl_valid"] = bool(domain_info.get("ssl_valid"))
    features["ssl_status"] = str(domain_info.get("ssl_status", "Unavailable"))

    return {
        "url": url,
        "classification": eval_result["classification"],
        "risk_score": eval_result["risk_score"],
        "technical_status": eval_result["technical_status"],
        "classification_reason": eval_result["classification_reason"],
        "rules_triggered": eval_result["rules_triggered"],
        "features": features,
        "domain_info": domain_info,
    }
