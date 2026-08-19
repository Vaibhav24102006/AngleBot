"""
tests/test_threat_intel_chaos.py

Step 7 — deterministic external-service chaos coverage for
threat_intel/threat_intel_client.py. Before this step there was no
automated test for this module at all — tests/test_threat_intel.py (now
renamed tests/manual_threat_intel_check.py, matching the Step 2 D9
convention for non-pytest diagnostic scripts) was a manual CLI script with
zero test_-prefixed functions, and would make a REAL network call if run
directly. This file replaces that gap with mocked requests.post/requests.get
— no network access, deterministic, no API keys required.
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
from unittest.mock import patch, MagicMock

from threat_intel.threat_intel_client import ThreatIntelClient


def _resp(status_code=200, json_data=None, raise_json_error=False):
    r = MagicMock()
    r.status_code = status_code
    if raise_json_error:
        r.json.side_effect = ValueError("invalid json")
    else:
        r.json.return_value = json_data or {}
    if status_code >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    else:
        r.raise_for_status.return_value = None
    return r


class TestMalwareBazaarChaos:
    @patch("threat_intel.threat_intel_client.requests.post")
    def test_success_known_match(self, mock_post):
        mock_post.return_value = _resp(200, {
            "query_status": "ok",
            "data": [{"signature": "RedLine Stealer", "first_seen": "2024-01-01"}],
        })
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result["malwarebazaar_match"] is True
        assert result["malware_family"] == "RedLine Stealer"

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_hash_not_found_is_a_known_negative_not_unknown(self, mock_post):
        mock_post.return_value = _resp(200, {"query_status": "hash_not_found"})
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result["malwarebazaar_match"] is False
        assert result.get("status") != "unknown"  # a real negative, not a failure

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_timeout_returns_unknown_not_raises(self, mock_post):
        mock_post.side_effect = requests.Timeout("timed out")
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_connection_error_returns_unknown_not_raises(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no route to host")
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_http_error_status_returns_unknown_not_raises(self, mock_post):
        mock_post.return_value = _resp(500)
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_malformed_json_returns_unknown_not_raises(self, mock_post):
        mock_post.return_value = _resp(200, raise_json_error=True)
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_unexpected_query_status_returns_unknown_not_raises(self, mock_post):
        """Neither 'ok' nor 'hash_not_found' — e.g. a rate-limit-style
        response the client doesn't have an explicit branch for."""
        mock_post.return_value = _resp(200, {"query_status": "rate_limited"})
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.requests.post")
    def test_missing_expected_fields_in_ok_response_falls_back_to_unknown_family(self, mock_post):
        mock_post.return_value = _resp(200, {"query_status": "ok", "data": [{}]})
        client = ThreatIntelClient()
        result = client.check_malwarebazaar("somehash")
        assert result["malwarebazaar_match"] is True
        assert result["malware_family"] == "Unknown"  # no fabricated family name


class TestVirusTotalChaos:
    def test_missing_api_key_returns_unknown_without_a_network_call(self):
        with patch("threat_intel.threat_intel_client.VT_API_KEY", ""):
            with patch("threat_intel.threat_intel_client.requests.get") as mock_get:
                client = ThreatIntelClient()
                result = client.check_virustotal("somehash")
                assert result["status"] == "unknown"
                mock_get.assert_not_called()

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_success_with_detections(self, mock_get):
        mock_get.return_value = _resp(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 12, "suspicious": 2, "undetected": 55, "harmless": 1,
            }}}
        })
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result["virus_total_detections"] == 12
        assert result["virus_total_total_engines"] == 70

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_404_is_a_known_negative_not_unknown(self, mock_get):
        mock_get.return_value = _resp(404)
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result["virus_total_detections"] == 0
        assert "status" not in result  # a real "not found", not a failure

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_timeout_returns_unknown_not_raises(self, mock_get):
        mock_get.side_effect = requests.Timeout("timed out")
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_rate_limit_status_returns_unknown_not_raises(self, mock_get):
        mock_get.return_value = _resp(429)
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_malformed_json_returns_unknown_not_raises(self, mock_get):
        mock_get.return_value = _resp(200, raise_json_error=True)
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result == {"status": "unknown"}

    @patch("threat_intel.threat_intel_client.VT_API_KEY", "fake-key-for-test")
    @patch("threat_intel.threat_intel_client.requests.get")
    def test_missing_expected_nested_fields_does_not_crash(self, mock_get):
        """A response missing last_analysis_stats entirely — a real
        malformed/partial-provider-response scenario."""
        mock_get.return_value = _resp(200, {"data": {"attributes": {}}})
        client = ThreatIntelClient()
        result = client.check_virustotal("somehash")
        assert result["virus_total_detections"] == 0
        assert result["virus_total_total_engines"] == 0


class TestGetReputationCombinedChaos:
    """get_reputation() combines both sources; these prove the combined
    behavior the pipeline actually relies on."""

    def test_both_sources_failing_returns_unknown(self):
        client = ThreatIntelClient()
        with patch.object(client, "check_malwarebazaar", return_value={"status": "unknown"}), \
             patch.object(client, "check_virustotal", return_value={"status": "unknown"}):
            result = client.get_reputation("somehash")
        assert result == {"status": "unknown"}

    def test_one_source_failing_still_yields_a_populated_result_from_the_other(self):
        """threat_intel_client.py's own documented ambiguity (not fixed
        here, see DECISIONS.md Step 7 P2): a partial failure is
        indistinguishable from a genuine negative on the failed side, but
        the call must not raise and must still surface the side that DID
        work."""
        client = ThreatIntelClient()
        with patch.object(client, "check_malwarebazaar", return_value={"status": "unknown"}), \
             patch.object(client, "check_virustotal", return_value={
                 "virus_total_detections": 40, "virus_total_total_engines": 70,
             }):
            result = client.get_reputation("somehash")
        assert result["virus_total_detections"] == 40
        assert result["confidence"] == "high"  # >=3 detections

    def test_high_detection_count_yields_high_confidence(self):
        client = ThreatIntelClient()
        with patch.object(client, "check_malwarebazaar", return_value={"malwarebazaar_match": False}), \
             patch.object(client, "check_virustotal", return_value={
                 "virus_total_detections": 3, "virus_total_total_engines": 70,
             }):
            result = client.get_reputation("somehash")
        assert result["confidence"] == "high"

    def test_low_nonzero_detection_count_yields_medium_confidence(self):
        client = ThreatIntelClient()
        with patch.object(client, "check_malwarebazaar", return_value={"malwarebazaar_match": False}), \
             patch.object(client, "check_virustotal", return_value={
                 "virus_total_detections": 1, "virus_total_total_engines": 70,
             }):
            result = client.get_reputation("somehash")
        assert result["confidence"] == "medium"

    def test_zero_detections_no_match_yields_low_confidence_not_fabricated_clean(self):
        client = ThreatIntelClient()
        with patch.object(client, "check_malwarebazaar", return_value={"malwarebazaar_match": False}), \
             patch.object(client, "check_virustotal", return_value={
                 "virus_total_detections": 0, "virus_total_total_engines": 70,
             }):
            result = client.get_reputation("somehash")
        assert result["confidence"] == "low"
        assert "clean" not in json.dumps(result).lower()
        assert "safe" not in json.dumps(result).lower()
