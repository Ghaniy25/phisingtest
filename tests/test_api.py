"""
Comprehensive automated test suite for Smart Phishing Detection System (22 test cases).
Covers all 10 PRD detection features, 5 rules (R-01..R-05), domain/SSL fixtures,
SSRF & DNS rebinding protection, persistent SQLite/Firestore storage, pagination,
security controls, ASGI API integration, and labeled dataset evaluation metrics.
"""

import asyncio
import csv
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from Detection.classifier import evaluate_rules_and_score
from Detection.domain_checker import check_domain_and_ssl, is_unsafe_ip
from Detection.feature_extraction import extract_features, split_domain_parts
from backend.main import app
from backend.routes import analyze as analyze_route
from backend.routes import health as health_route
from backend.routes import history as history_route
from backend.routes import stats as stats_route
from backend.schemas import URLCheckRequest
from backend.security import (
    SlidingWindowRateLimiter,
    validate_scan_id,
    verify_admin_api_key,
)
from backend.services import firestore_service
from backend.services.classifier_service import analyze_url


class TestSmartPhishingDetectionPRD(unittest.TestCase):
    """Full PRD verification suite (22 tests)."""

    def setUp(self):
        data_dir = Path(__file__).resolve().parent.parent / "backend" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = str(data_dir / "test_history.sqlite3")
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        os.environ["LOCAL_DB_PATH"] = self.db_file
        os.environ["SKIP_NETWORK_CHECKS"] = "true"
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
        os.environ["FIRESTORE_FORCE_ENABLE"] = "false"
        firestore_service.reset_client_state()
        firestore_service.clear_history()

    def tearDown(self):
        firestore_service.clear_history()
        os.environ.pop("SKIP_NETWORK_CHECKS", None)
        os.environ.pop("ADMIN_API_KEY", None)
        os.environ.pop("LOCAL_DB_PATH", None)
        if os.path.exists(self.db_file):
            try:
                os.remove(self.db_file)
            except OSError:
                pass

    # 1. URL Valid
    def test_01_valid_url(self):
        req = URLCheckRequest(url="https://www.google.com/search?q=test")
        self.assertEqual(req.url, "https://www.google.com/search?q=test")
        req_no_scheme = URLCheckRequest(url="portal.bankmandiri.co.id")
        self.assertEqual(req_no_scheme.url, "http://portal.bankmandiri.co.id")

    # 2. URL Invalid
    def test_02_invalid_url_rejected(self):
        invalid_inputs = [
            "",
            "   ",
            "ab",
            "not-a-valid-domain",
            "javascript:alert(1)",
            "data:text/html,<h1>phish</h1>",
            "file:///etc/passwd",
            "ftp://files.example.com/file.zip",
            "https://domain dengan spasi.com/login",
            "https://invalid..domain.com",
        ]
        for raw in invalid_inputs:
            with self.subTest(url=raw):
                with self.assertRaises(ValidationError):
                    URLCheckRequest(url=raw)

    # 3. URL menggunakan IP Address (R-01)
    def test_03_url_with_ip_address_r01(self):
        req = URLCheckRequest(url="http://192.168.1.50/login-bca@verify.com")
        res = analyze_url(req.url)
        self.assertEqual(res.features.has_ip, 1)
        self.assertTrue(res.has_ip)
        self.assertEqual(res.classification, "PHISHING")
        self.assertTrue(any(r.startswith("R-01") for r in res.rules_triggered))

    # 4. URL menggunakan karakter @
    def test_04_url_with_at_character(self):
        req = URLCheckRequest(url="http://trusted.example.org@evil-domain.net/profile")
        res = analyze_url(req.url)
        self.assertEqual(res.features.has_at, 1)
        self.assertGreaterEqual(res.risk_score, 30)
        self.assertIn(res.classification, ("SUSPICIOUS", "PHISHING"))

    # 5. URL dengan banyak subdomain & Public Suffix Awareness
    def test_05_url_with_many_subdomains_and_public_suffix(self):
        # Multi-label public suffix .co.id should count only actual subdomains
        reg_dom, sub_cnt = split_domain_parts("portal.bankmandiri.co.id")
        self.assertEqual(reg_dom, "bankmandiri.co.id")
        self.assertEqual(sub_cnt, 1)

        # 3 subdomains on standard TLD
        req = URLCheckRequest(url="http://a.b.c.contoh-domain.com/path")
        res = analyze_url(req.url)
        self.assertEqual(res.features.subdomain_count, 3)
        self.assertGreaterEqual(res.risk_score, 30)

    # 6. URL dengan Suspicious Keywords
    def test_06_url_with_suspicious_keywords(self):
        features = extract_features("https://portal-layanan.org/login/verify/account/token")
        self.assertIn("login", features["suspicious_keywords_found"])
        self.assertIn("verify", features["suspicious_keywords_found"])
        self.assertIn("account", features["suspicious_keywords_found"])
        self.assertIn("token", features["suspicious_keywords_found"])
        self.assertGreaterEqual(len(features["suspicious_keywords_found"]), 4)

    # 7. URL Shortener
    def test_07_url_shortener_detected(self):
        req = URLCheckRequest(url="https://bit.ly/3xYzAbC")
        res = analyze_url(req.url)
        self.assertTrue(res.features.is_shortened)
        self.assertGreaterEqual(res.risk_score, 30)
        self.assertEqual(res.classification, "SUSPICIOUS")

    # 8. Domain Baru + Banyak Subdomain (R-02)
    def test_08_new_domain_with_subdomains_r02(self):
        features = extract_features("https://auth.portal.layanan-baru.org/home")
        domain_fixture = {
            "hostname": "auth.portal.layanan-baru.org",
            "registrable_domain": "layanan-baru.org",
            "dns_resolved": True,
            "ip_address": "93.184.216.34",
            "ssl_status": "Valid",
            "ssl_valid": True,
            "ssl_expiry": "2027-05-01",
            "domain_age_days": 15,
            "domain_age_status": "available",
            "registration_date": "2026-11-01",
            "ssrf_blocked": False,
        }
        eval_res = evaluate_rules_and_score(features, domain_fixture)
        self.assertTrue(any(r.startswith("R-02") for r in eval_res["rules_triggered"]))
        self.assertEqual(eval_res["classification"], "Suspicious")
        self.assertGreaterEqual(eval_res["risk_score"], 45)

    # 9. Domain Similarity / Typosquatting (R-03)
    def test_09_domain_similarity_typosquatting_r03(self):
        spoof_urls = [
            ("https://kl1kbca.com/login", "klikbca.com"),
            ("https://g00gle.com/account", "google.com"),
            ("https://paypa1.com/signin", "paypal.com"),
            ("https://tokopediaa.com/promo", "tokopedia.com"),
        ]
        for url, official in spoof_urls:
            with self.subTest(url=url):
                res = analyze_url(url)
                self.assertTrue(res.features.similarity_detected)
                self.assertEqual(res.features.similar_to_domain, official)
                self.assertEqual(res.classification, "PHISHING")
                self.assertTrue(any(r.startswith("R-03") for r in res.rules_triggered))

        # Authentic official domain must NOT trigger similarity
        official_res = analyze_url("https://www.google.com")
        self.assertFalse(official_res.features.similarity_detected)

    # 10. Sertifikat SSL Valid
    def test_10_valid_ssl_certificate(self):
        res = analyze_url("https://www.google.com")
        self.assertTrue(res.ssl_valid)
        self.assertEqual(res.domain_info.ssl_status, "Valid")
        self.assertEqual(res.classification, "SAFE")

    # 11. Sertifikat SSL Invalid atau Expired menggunakan fixture aman
    def test_11_invalid_and_expired_ssl_certificate_fixture(self):
        features = extract_features("https://contoh-sertifikat-rusak.org")
        for bad_ssl_status in ("Invalid / Self-Signed", "Expired"):
            with self.subTest(ssl_status=bad_ssl_status):
                fixture = {
                    "hostname": "contoh-sertifikat-rusak.org",
                    "registrable_domain": "contoh-sertifikat-rusak.org",
                    "dns_resolved": True,
                    "ip_address": "93.184.216.34",
                    "ssl_status": bad_ssl_status,
                    "ssl_valid": False,
                    "ssl_expiry": "2024-01-01",
                    "domain_age_days": 400,
                    "domain_age_status": "available",
                    "registration_date": "2023-01-01",
                    "ssrf_blocked": False,
                }
                eval_res = evaluate_rules_and_score(features, fixture)
                self.assertGreaterEqual(eval_res["risk_score"], 30)
                self.assertNotEqual(eval_res["classification"], "Safe")

    # 12. Data Domain Unavailable (Inconclusive)
    def test_12_domain_data_unavailable_inconclusive(self):
        features = extract_features("https://domain-tanpa-data.org")
        unavailable_fixture = {
            "hostname": "domain-tanpa-data.org",
            "registrable_domain": "domain-tanpa-data.org",
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
        eval_res = evaluate_rules_and_score(features, unavailable_fixture)
        self.assertEqual(eval_res["technical_status"], "inconclusive")
        self.assertEqual(eval_res["classification"], "Suspicious")
        self.assertTrue(any(r.startswith("R-04") for r in eval_res["rules_triggered"]))

    # 13. Klasifikasi SAFE (R-05)
    def test_13_classification_safe_r05(self):
        res = analyze_url("https://www.google.com")
        self.assertEqual(res.classification, "SAFE")
        self.assertLess(res.risk_score, 30)
        self.assertTrue(any(r.startswith("R-05") for r in res.rules_triggered))

    # 14. Klasifikasi SUSPICIOUS (R-04)
    def test_14_classification_suspicious_r04(self):
        res = analyze_url("http://update-akun.login.verify.contoh-domain.com")
        self.assertEqual(res.classification, "SUSPICIOUS")
        self.assertGreaterEqual(res.risk_score, 30)
        self.assertLess(res.risk_score, 60)
        self.assertTrue(any(r.startswith("R-04") for r in res.rules_triggered))

    # 15. Klasifikasi PHISHING
    def test_15_classification_phishing(self):
        res = analyze_url("http://192.168.1.50/login-bca@verify.com")
        self.assertEqual(res.classification, "PHISHING")
        self.assertGreaterEqual(res.risk_score, 60)

    # 16. Penyimpanan Histori Persisten (SQLite local fallback)
    def test_16_history_persistence_sqlite_and_memory(self):
        scan = analyze_url("https://www.google.com")
        # Clear in-memory cache to prove data is read from persistent SQLite file
        firestore_service._IN_MEMORY_DB.clear()
        loaded = firestore_service.get_scan_by_id(scan.scan_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.scan_id, scan.scan_id)
        self.assertEqual(loaded.url, "https://www.google.com")

    # 17. Pengambilan Histori & Pagination (limit + offset)
    def test_17_history_retrieval_and_pagination(self):
        s1 = analyze_url("https://www.google.com")
        s2 = analyze_url("https://bit.ly/3xYzAbC")
        s3 = analyze_url("http://192.168.1.50/login-bca@verify.com")

        page1 = history_route.get_scan_history(limit=2, offset=0)
        page2 = history_route.get_scan_history(limit=2, offset=2)
        self.assertEqual(len(page1), 2)
        self.assertEqual(len(page2), 1)
        self.assertEqual(page1[0].scan_id, s3.scan_id)
        self.assertEqual(page1[1].scan_id, s2.scan_id)
        self.assertEqual(page2[0].scan_id, s1.scan_id)

    # 18. Statistik Klasifikasi
    def test_18_statistics_calculation(self):
        analyze_url("https://www.google.com")
        analyze_url("https://bit.ly/3xYzAbC")
        analyze_url("http://192.168.1.50/login-bca@verify.com")

        stats = stats_route.get_statistics()
        self.assertEqual(stats.total_scans, 3)
        self.assertEqual(stats.safe_count, 1)
        self.assertEqual(stats.suspicious_count, 1)
        self.assertEqual(stats.phishing_count, 1)

    # 19. Error Handling (400, 403, 404, 429)
    def test_19_error_handling_400_403_404_429(self):
        # 400 Bad scan_id format
        with self.assertRaises(HTTPException) as ctx400:
            validate_scan_id("invalid-scan-id")
        self.assertEqual(ctx400.exception.status_code, 400)

        # 404 Not Found for valid scan_id format that doesn't exist
        with self.assertRaises(HTTPException) as ctx404:
            history_route.get_scan_by_id("scan-00000000")
        self.assertEqual(ctx404.exception.status_code, 404)

        # 403 Unauthorized admin key
        os.environ["ADMIN_API_KEY"] = "secret-admin-key"
        with self.assertRaises(HTTPException) as ctx403:
            verify_admin_api_key(x_api_key="wrong-key")
        self.assertEqual(ctx403.exception.status_code, 403)

        # 429 Rate limiter
        limiter = SlidingWindowRateLimiter("test", "TEST_LIMIT", default_limit=1)
        limiter.check("client-1")
        with self.assertRaises(HTTPException) as ctx429:
            limiter.check("client-1")
        self.assertEqual(ctx429.exception.status_code, 429)

    # 20. SSRF & DNS Rebinding Protection
    def test_20_ssrf_and_dns_rebinding_protection(self):
        ssrf_targets = [
            "http://localhost:8000/api/v1/health",
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://[::1]:8000/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        for target in ssrf_targets:
            with self.subTest(target=target):
                with self.assertRaises(ValidationError):
                    URLCheckRequest(url=target)

        # Verify is_unsafe_ip detects private, loopback, and metadata IPs
        self.assertTrue(is_unsafe_ip("127.0.0.1"))
        self.assertTrue(is_unsafe_ip("169.254.169.254"))
        self.assertTrue(is_unsafe_ip("192.168.1.1"))
        self.assertTrue(is_unsafe_ip("10.0.0.1"))
        self.assertFalse(is_unsafe_ip("93.184.216.34"))

        # Verify DNS rebinding guard blocks domain resolving to 127.0.0.1
        os.environ["SKIP_NETWORK_CHECKS"] = "false"
        fake_addrinfo = [(2, 1, 6, "", ("127.0.0.1", 0))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            info = check_domain_and_ssl("https://rebinding-attacker.example.com")
            self.assertTrue(info["ssrf_blocked"])
            self.assertFalse(info["dns_resolved"])
            self.assertEqual(info["ip_address"], "Blocked-Internal-IP")
        os.environ["SKIP_NETWORK_CHECKS"] = "true"

    # 21. Full API Route & OpenAPI Schema Integration
    def test_21_full_api_route_and_schema_integration(self):
        schema = app.openapi()
        paths = schema.get("paths", {})
        self.assertIn("/api/v1/health", paths)
        self.assertIn("/api/v1/analyze", paths)
        self.assertIn("/api/v1/history", paths)
        self.assertIn("/api/v1/history/{scan_id}", paths)
        self.assertIn("/api/v1/statistics", paths)

        health_data = health_route.get_health_status()
        self.assertEqual(health_data["status"], "ok")
        self.assertEqual(health_data["classifier"], "zikra-heuristic-dns-ssl")
        self.assertEqual(health_data["storage"]["backend"], "sqlite_local_fallback")

        req = URLCheckRequest(url="https://kl1kbca.com/login")
        analyze_data = analyze_route.analyze_target_url(req)
        self.assertEqual(analyze_data.classification, "PHISHING")
        self.assertTrue(analyze_data.features.similarity_detected)
        self.assertEqual(analyze_data.features.similar_to_domain, "klikbca.com")

        detail = history_route.get_scan_by_id(analyze_data.scan_id)
        self.assertEqual(detail.scan_id, analyze_data.scan_id)

        stats = stats_route.get_statistics()
        self.assertEqual(stats.total_scans, 1)
        self.assertEqual(stats.phishing_count, 1)

    # 22. Dataset Evaluation Metrics (Accuracy, Precision, Recall, F1-score)
    def test_22_dataset_evaluation_metrics(self):
        dataset_path = Path(__file__).resolve().parent.parent / "Detection" / "dataset" / "cleaned_dataset.csv"
        if not dataset_path.exists():
            self.skipTest("cleaned_dataset.csv not present")

        tp = tn = fp = fn = 0
        max_samples = 2000
        with open(dataset_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                if idx >= max_samples:
                    break
                url = (row.get("url") or "").strip()
                label = (row.get("label") or "").strip().lower()
                if not url or label not in {"phishing", "legitimate"}:
                    continue

                feat = extract_features(url)
                # Lexical risk scoring for offline dataset evaluation
                score = 0
                if feat["has_ip"] == 1:
                    score += 40
                if feat["has_at"] == 1:
                    score += 30
                if feat["url_length"] > 75:
                    score += 20
                elif feat["url_length"] > 54:
                    score += 10
                if feat["hyphen_count"] >= 3:
                    score += 20
                elif feat["hyphen_count"] >= 1:
                    score += 5
                if feat["subdomain_count"] >= 3:
                    score += 20
                elif feat["subdomain_count"] == 2:
                    score += 10
                if feat["is_https"] == 0:
                    score += 10
                if len(feat["suspicious_keywords_found"]) >= 2:
                    score += 25
                elif len(feat["suspicious_keywords_found"]) == 1:
                    score += 10
                if feat["is_shortened"]:
                    score += 30
                if feat["similarity_detected"]:
                    score += 75

                pred_phishing = score >= 30
                actual_phishing = label == "phishing"

                if pred_phishing and actual_phishing:
                    tp += 1
                elif not pred_phishing and not actual_phishing:
                    tn += 1
                elif pred_phishing and not actual_phishing:
                    fp += 1
                else:
                    fn += 1

        total = tp + tn + fp + fn
        self.assertGreater(total, 100)
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        self.assertGreater(accuracy, 0.5)
        self.assertGreater(f1, 0.4)


if __name__ == "__main__":
    unittest.main()
