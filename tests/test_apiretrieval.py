from __future__ import annotations

import json
import os
import requests
import pytest
from unittest.mock import patch, MagicMock

import APIRetrieval


class TestAPIRetrievalHelperFunctions:
    def test_maybe_b64_decode_plain_and_encoded(self):
        # Plain text password
        assert APIRetrieval._maybe_b64_decode("MySecretPass123!") == "MySecretPass123!"
        
        # Base64 encoded password ("MySecretPass123!" -> "TXlTZWNyZXRQYXNzMTIzIQ==")
        encoded = "TXlTZWNyZXRQYXNzMTIzIQ=="
        assert APIRetrieval._maybe_b64_decode(encoded) == "MySecretPass123!"

        # Empty string handling
        assert APIRetrieval._maybe_b64_decode("") == ""
        assert APIRetrieval._maybe_b64_decode("   ") == ""

    def test_is_expired_token_response(self):
        # Test 1: None response
        assert APIRetrieval._is_expired_token_response(None) is False

        # Test 2: HTTP 500 with NetWitness JSON error "Expired Token"
        res_500 = requests.Response()
        res_500.status_code = 500
        res_500._content = json.dumps({
            "status": 500,
            "timestamp": "2026-07-28T05:57:59.210Z",
            "errors": [{"message": "Expired Token"}]
        }).encode("utf-8")
        res_500.encoding = "utf-8"
        assert APIRetrieval._is_expired_token_response(res_500) is True

        # Test 3: HTTP 401 with text containing "token expired"
        res_401 = requests.Response()
        res_401.status_code = 401
        res_401._content = b'{"message": "The provided token expired at 2026-07-28"}'
        res_401.encoding = "utf-8"
        assert APIRetrieval._is_expired_token_response(res_401) is True

        # Test 4: HTTP 200 OK (valid response)
        res_200 = requests.Response()
        res_200.status_code = 200
        res_200._content = b'[{"id": "INC-123"}]'
        res_200.encoding = "utf-8"
        assert APIRetrieval._is_expired_token_response(res_200) is False

        # Test 5: HTTP 500 unrelated server error
        res_500_other = requests.Response()
        res_500_other.status_code = 500
        res_500_other._content = b'{"status":500, "errors":[{"message":"Database connection timeout"}]}'
        res_500_other.encoding = "utf-8"
        assert APIRetrieval._is_expired_token_response(res_500_other) is False


class TestAPIRetrievalAuthentication:
    def test_authenticate_netwitness_success(self, monkeypatch):
        mock_res = requests.Response()
        mock_res.status_code = 200
        mock_res._content = json.dumps({"accessToken": "NEW_SESSION_TOKEN_12345"}).encode("utf-8")
        mock_res.encoding = "utf-8"

        with patch("requests.post", return_value=mock_res) as mock_post:
            token = APIRetrieval.authenticate_netwitness("https://192.168.20.11", "admin", "secret")
            assert token == "NEW_SESSION_TOKEN_12345"
            assert os.environ.get("NW_TOKEN") == "NEW_SESSION_TOKEN_12345"
            assert os.environ.get("NETWITNESS_TOKEN") == "NEW_SESSION_TOKEN_12345"
            mock_post.assert_called_once()

    def test_authenticate_netwitness_failure(self):
        mock_res = requests.Response()
        mock_res.status_code = 401
        mock_res._content = b'{"message": "Invalid username or password"}'
        mock_res.encoding = "utf-8"

        with patch("requests.post", return_value=mock_res):
            with pytest.raises(RuntimeError) as exc_info:
                APIRetrieval.authenticate_netwitness("https://192.168.20.11", "admin", "wrong_pass")
            assert "Authentication failed (HTTP 401)" in str(exc_info.value)

    def test_get_auth_token_with_username_and_password(self, monkeypatch):
        monkeypatch.setenv("NW_HOST", "https://192.168.20.11")
        monkeypatch.setenv("NW_USERNAME", "analyst_user")
        monkeypatch.setenv("NW_PASSWORD", "analyst_pass")
        monkeypatch.delenv("NW_TOKEN", raising=False)
        monkeypatch.delenv("NETWITNESS_TOKEN", raising=False)

        mock_res = requests.Response()
        mock_res.status_code = 200
        mock_res._content = json.dumps({"accessToken": "DYNAMIC_TOKEN_9999"}).encode("utf-8")
        mock_res.encoding = "utf-8"

        with patch("requests.post", return_value=mock_res):
            token = APIRetrieval.get_auth_token(force_refresh=True)
            assert token == "DYNAMIC_TOKEN_9999"


class TestAPIRetrievalFetchAutoReauth:
    def test_fetch_incident_via_fetch_api_auto_reauthenticates(self, monkeypatch):
        monkeypatch.setenv("NW_HOST", "https://192.168.20.11")
        monkeypatch.setenv("NW_USERNAME", "admin")
        monkeypatch.setenv("NW_PASSWORD", "secret")

        expired_res = requests.Response()
        expired_res.status_code = 500
        expired_res._content = json.dumps({
            "status": 500,
            "errors": [{"message": "Expired Token"}]
        }).encode("utf-8")
        expired_res.encoding = "utf-8"

        login_res = requests.Response()
        login_res.status_code = 200
        login_res._content = json.dumps({"accessToken": "REFRESHED_TOKEN_555"}).encode("utf-8")
        login_res.encoding = "utf-8"

        success_res = requests.Response()
        success_res.status_code = 200
        success_res._content = json.dumps([{"id": "INC-52964", "title": "Test Incident"}]).encode("utf-8")
        success_res.encoding = "utf-8"

        get_calls = []

        def mock_get(url, headers=None, data=None, verify=False, timeout=15):
            get_calls.append(headers.get("NetWitness-Token"))
            if headers.get("NetWitness-Token") == "EXPIRED_TOKEN_111":
                return expired_res
            elif headers.get("NetWitness-Token") == "REFRESHED_TOKEN_555":
                return success_res
            return expired_res

        with patch("requests.get", side_effect=mock_get), \
             patch("requests.post", return_value=login_res):

            result = APIRetrieval.fetch_incident_via_fetch_api(
                "https://192.168.20.11", "EXPIRED_TOKEN_111", "INC-52964"
            )

            assert result.get("id") == "INC-52964"
            assert get_calls == ["EXPIRED_TOKEN_111", "REFRESHED_TOKEN_555"]

    def test_fetch_alerts_via_fetch_api_auto_reauthenticates(self, monkeypatch):
        monkeypatch.setenv("NW_HOST", "https://192.168.20.11")
        monkeypatch.setenv("NW_USERNAME", "admin")
        monkeypatch.setenv("NW_PASSWORD", "secret")

        expired_res = requests.Response()
        expired_res.status_code = 500
        expired_res._content = json.dumps({
            "status": 500,
            "errors": [{"message": "Expired Token"}]
        }).encode("utf-8")
        expired_res.encoding = "utf-8"

        login_res = requests.Response()
        login_res.status_code = 200
        login_res._content = json.dumps({"accessToken": "FRESH_ALERT_TOKEN"}).encode("utf-8")
        login_res.encoding = "utf-8"

        alerts_res = requests.Response()
        alerts_res.status_code = 200
        alerts_res._content = json.dumps([{"id": "ALERT-1", "name": "PowerShell Execution"}]).encode("utf-8")
        alerts_res.encoding = "utf-8"

        def mock_get(url, headers=None, data=None, verify=False, timeout=30):
            if headers.get("NetWitness-Token") == "EXPIRED_ALERT_TOKEN":
                return expired_res
            return alerts_res

        with patch("requests.get", side_effect=mock_get), \
             patch("requests.post", return_value=login_res):

            alerts = APIRetrieval.fetch_alerts_via_fetch_api(
                "https://192.168.20.11", "EXPIRED_ALERT_TOKEN", "INC-52964"
            )

            assert len(alerts) == 1
            assert alerts[0]["id"] == "ALERT-1"


class TestAPIRetrievalComprehensivePayload:
    def test_get_comprehensive_incident_payload_disk_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        export_file = tmp_path / "incident_INC-99999_respond_api_export.json"
        export_file.write_text(json.dumps({
            "incident": {"id": "INC-99999", "title": "Disk Export Test"},
            "alerts": [{"id": "ALERT-DISK"}]
        }), encoding="utf-8")

        payload = APIRetrieval.get_comprehensive_incident_payload("INC-99999")
        assert payload.get("incident", {}).get("id") == "INC-99999"
        assert len(payload.get("alerts", [])) == 1

    def test_get_comprehensive_incident_payload_live_fetch(self, monkeypatch):
        monkeypatch.setenv("NW_HOST", "https://192.168.20.11")
        monkeypatch.setenv("NW_USERNAME", "admin")
        monkeypatch.setenv("NW_PASSWORD", "secret")

        with patch("APIRetrieval.fetch_incident_via_fetch_api", return_value={"id": "INC-LIVE-1", "title": "Live Test"}), \
             patch("APIRetrieval.fetch_alerts_via_fetch_api", return_value=[{"id": "ALERT-LIVE"}]), \
             patch("APIRetrieval.get_auth_token", return_value="TOKEN_LIVE"):

            payload = APIRetrieval.get_comprehensive_incident_payload("INC-LIVE-1")
            assert payload["incident"]["id"] == "INC-LIVE-1"
            assert len(payload["alerts"]) == 1
