"""Automated unit and integration tests for Smart Phishing Detection API."""

import unittest
from backend.services.mock_classifier import analyze_url, MOCK_HISTORY_DB
from backend.schemas import URLCheckResponse, FeatureDetails


class TestMockClassifier(unittest.TestCase):
    """Test suite for Mock Classification Engine logic."""

    def test_phishing_classification_with_ip(self):
        url = "http://192.168.1.50/login.php"
        result = analyze_url(url)
        self.assertEqual(result.classification, "PHISHING")
        self.assertGreaterEqual(result.risk_score, 80)
        self.assertLessEqual(result.risk_score, 98)
        self.assertTrue(result.features.has_ip)
        self.assertIn("R-01: Direct IP address or high-risk keywords used", result.rules_triggered)

    def test_phishing_classification_with_multiple_keywords(self):
        url = "https://secure-update-account-verify.com"
        result = analyze_url(url)
        self.assertEqual(result.classification, "PHISHING")
        self.assertGreaterEqual(result.risk_score, 80)
        self.assertGreaterEqual(len(result.features.suspicious_keywords_found), 2)

    def test_suspicious_classification_with_http_or_single_keyword(self):
        url = "http://my-blog-news.com/verify"
        result = analyze_url(url)
        self.assertEqual(result.classification, "SUSPICIOUS")
        self.assertGreaterEqual(result.risk_score, 45)
        self.assertLessEqual(result.risk_score, 75)
        self.assertIn("R-02: Suspicious URL patterns or missing HTTPS", result.rules_triggered)

    def test_safe_classification_legitimate_url(self):
        url = "https://www.google.com"
        result = analyze_url(url)
        self.assertEqual(result.classification, "SAFE")
        self.assertGreaterEqual(result.risk_score, 5)
        self.assertLessEqual(result.risk_score, 25)
        self.assertIn("R-05: Standard legitimate URL features", result.rules_triggered)

    def test_history_persistence(self):
        initial_count = len(MOCK_HISTORY_DB)
        new_url = "https://verified-safe-portal-example.org"
        scan = analyze_url(new_url)
        self.assertEqual(len(MOCK_HISTORY_DB), initial_count + 1)
        self.assertEqual(MOCK_HISTORY_DB[0].scan_id, scan.scan_id)


if __name__ == "__main__":
    unittest.main()

