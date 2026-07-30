"""
[FYP-FILE]
# Important dependencies: APIRetrieval, __future__, json, os, pytest, requests, unittest.
File: tests/test_apiretrieval.py
Purpose: Verifies APIRetrieval.py — the standalone NetWitness Respond REST
    API client used to pull an incident's raw details/alerts (the first
    step of the SOC pipeline, ahead of Parsing & Normalisation). Covers
    credential decoding, NetWitness session-token authentication, the
    "Expired Token" detection heuristic and its automatic
    re-authenticate-and-retry behaviour, and the disk-cache-first
    comprehensive-payload assembly used by the rest of the pipeline.
Main functionalities: Exercises _maybe_b64_decode() and
    _is_expired_token_response() as pure helpers; mocks requests.post/
    requests.get to drive authenticate_netwitness(), get_auth_token(),
    fetch_incident_via_fetch_api() and fetch_alerts_via_fetch_api() through
    both a clean success path and an expired-token-then-reauthenticate
    path; and drives get_comprehensive_incident_payload() through both its
    "load a previously exported *_respond_api_export.json from disk" path
    and its "no cached file, fetch live from NetWitness" path.
Inputs: unittest.mock.patch() on requests.post/requests.get returning
    hand-built requests.Response objects (status_code + raw JSON _content);
    monkeypatch.setenv() for NW_HOST/NW_USERNAME/NW_PASSWORD/NW_TOKEN; a
    tmp_path with a synthetic *_respond_api_export.json for the disk-cache
    test. No real NetWitness host, network call, or credentials are used —
    all example hosts/tokens/passwords in this file are fixtures, not
    live secrets.
Outputs: Assertions on returned tokens/dicts/lists, on os.environ
    NW_TOKEN/NETWITNESS_TOKEN caching after authentication, on the ordered
    sequence of tokens sent across retried requests.get() calls, and on
    RuntimeError being raised (with the expected message) for a failed
    login.
Workflow position: Data-acquisition layer feeding the SOC pipeline —
    upstream of tests/test_parsing_only.py's Parsing & Normalisation stage,
    which consumes the payload get_comprehensive_incident_payload() builds.
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_apiretrieval.py`.
Calls: APIRetrieval — _maybe_b64_decode(), _is_expired_token_response(),
    authenticate_netwitness(), get_auth_token(),
    fetch_incident_via_fetch_api(), fetch_alerts_via_fetch_api(),
    get_comprehensive_incident_payload().
Key evaluator search terms: APIRetrieval, NetWitness, authenticate_netwitness,
    get_auth_token, Expired Token, fetch_incident_via_fetch_api,
    fetch_alerts_via_fetch_api, get_comprehensive_incident_payload,
    respond_api_export.
[/FYP-FILE]
"""
from __future__ import annotations

import json
import os
import requests
import pytest
from unittest.mock import patch, MagicMock

import APIRetrieval


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Pure helper functions — base64 credential decoding and the
# "expired token" response-shape heuristic
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestAPIRetrievalHelperFunctions` — owns TestAPIRetrievalHelperFunctions state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_maybe_b64_decode_plain_and_encoded, test_is_expired_token_response.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestAPIRetrievalHelperFunctions:
    def test_maybe_b64_decode_plain_and_encoded(self):
        """[FYP-FUNCTION] Validates APIRetrieval._maybe_b64_decode() accepts
        a NetWitness password supplied either as plain text (returned
        unchanged) or base64-encoded (decoded), and that blank/whitespace-
        only input returns an empty string rather than raising."""
        # Plain text password
        assert APIRetrieval._maybe_b64_decode("MySecretPass123!") == "MySecretPass123!"
        
        # Base64 encoded password ("MySecretPass123!" -> "TXlTZWNyZXRQYXNzMTIzIQ==")
        encoded = "TXlTZWNyZXRQYXNzMTIzIQ=="
        assert APIRetrieval._maybe_b64_decode(encoded) == "MySecretPass123!"

        # Empty string handling
        assert APIRetrieval._maybe_b64_decode("") == ""
        assert APIRetrieval._maybe_b64_decode("   ") == ""

    # [FYP-EVALUATOR]
    def test_is_expired_token_response(self):
        """[FYP-FUNCTION] Validates APIRetrieval._is_expired_token_response()
        classifies a NetWitness HTTP response as an expired-token failure
        only when it actually is one: a None response, a 200 OK, and an
        unrelated 500 (database timeout) all return False; an HTTP 500 with
        a NetWitness JSON "Expired Token" error message and an HTTP 401
        whose body text contains "token expired" both return True. This
        heuristic is what triggers the automatic re-authenticate-and-retry
        path in fetch_incident_via_fetch_api()/fetch_alerts_via_fetch_api()."""
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


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] NetWitness session-token authentication
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestAPIRetrievalAuthentication` — owns TestAPIRetrievalAuthentication state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_authenticate_netwitness_success, test_authenticate_netwitness_failure, test_get_auth_token_with_username_and_password.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestAPIRetrievalAuthentication:
    def test_authenticate_netwitness_success(self, monkeypatch):
        """[FYP-FUNCTION] Validates APIRetrieval.authenticate_netwitness()
        on a successful login: mocks requests.post() to return an
        accessToken, asserts the returned token matches it and that it is
        also cached into both the NW_TOKEN and NETWITNESS_TOKEN
        environment variables for subsequent calls to reuse."""
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
        """[FYP-FUNCTION] Validates APIRetrieval.authenticate_netwitness()
        raises RuntimeError with an "Authentication failed (HTTP 401)"
        message when NetWitness rejects the credentials, rather than
        returning a falsy/None token."""
        mock_res = requests.Response()
        mock_res.status_code = 401
        mock_res._content = b'{"message": "Invalid username or password"}'
        mock_res.encoding = "utf-8"

        with patch("requests.post", return_value=mock_res):
            with pytest.raises(RuntimeError) as exc_info:
                APIRetrieval.authenticate_netwitness("https://192.168.20.11", "admin", "wrong_pass")
            assert "Authentication failed (HTTP 401)" in str(exc_info.value)

    def test_get_auth_token_with_username_and_password(self, monkeypatch):
        """[FYP-FUNCTION] Validates APIRetrieval.get_auth_token(force_refresh=True)
        ignores any previously cached NW_TOKEN/NETWITNESS_TOKEN and
        performs a fresh login using NW_HOST/NW_USERNAME/NW_PASSWORD from
        the environment, returning the newly issued token."""
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


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Automatic re-authenticate-and-retry on an expired token
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestAPIRetrievalFetchAutoReauth` — owns TestAPIRetrievalFetchAutoReauth state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_fetch_incident_via_fetch_api_auto_reauthenticates, test_fetch_alerts_via_fetch_api_auto_reauthenticates.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestAPIRetrievalFetchAutoReauth:
    def test_fetch_incident_via_fetch_api_auto_reauthenticates(self, monkeypatch):
        """[FYP-FUNCTION] Validates APIRetrieval.fetch_incident_via_fetch_api()'s
        transparent recovery from a stale token: the first requests.get()
        call (with the caller-supplied expired token) is scripted to return
        the "Expired Token" error shape, which must trigger a fresh
        requests.post() login and a second requests.get() retry using the
        newly issued token. Asserts the final incident dict is returned and
        that get_calls records exactly the expired token followed by the
        refreshed token, in that order — i.e. exactly one silent retry, not
        a retry loop."""
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

        # [FYP-FUNCTION] `mock_get` — implements the mock get operation used by the surrounding test and validation workflow.
        # [FYP-INPUT] Parameters: `url`, `headers`, `data`, `verify`, `timeout`; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
        # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
        # [FYP-CALLS] Calls: `append`, `get`.
        # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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
        """[FYP-FUNCTION] Validates APIRetrieval.fetch_alerts_via_fetch_api()
        has the same auto-reauthenticate behaviour as
        fetch_incident_via_fetch_api() (above), but for the alerts-listing
        endpoint: an expired-token response triggers a fresh login, and the
        retried call with the refreshed token returns the alert list."""
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

        # [FYP-FUNCTION] `mock_get` — implements the mock get operation used by the surrounding test and validation workflow.
        # [FYP-INPUT] Parameters: `url`, `headers`, `data`, `verify`, `timeout`; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
        # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
        # [FYP-CALLS] Calls: `get`.
        # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

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


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] get_comprehensive_incident_payload() — disk cache vs. live
# fetch assembly
# ══════════════════════════════════════════════════════════════════════════

# [FYP-CLASS] `TestAPIRetrievalComprehensivePayload` — owns TestAPIRetrievalComprehensivePayload state or behaviour for the test and validation component.
# [FYP-PROCESS] Important methods: test_get_comprehensive_incident_payload_disk_file, test_get_comprehensive_incident_payload_live_fetch.
# [FYP-USED-BY] No direct caller confidently identified; the class may be instantiated dynamically or by an entry point.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class TestAPIRetrievalComprehensivePayload:
    def test_get_comprehensive_incident_payload_disk_file(self, tmp_path, monkeypatch):
        """[FYP-FUNCTION] Validates
        APIRetrieval.get_comprehensive_incident_payload() prefers a
        previously exported "incident_<id>_respond_api_export.json" file on
        disk (in the current working directory) over making any live
        NetWitness call, and returns its incident/alerts content unchanged."""
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
        """[FYP-FUNCTION] Validates
        APIRetrieval.get_comprehensive_incident_payload() falls back to a
        live fetch (fetch_incident_via_fetch_api() +
        fetch_alerts_via_fetch_api(), authenticated via get_auth_token())
        when no cached export file exists on disk, and assembles their
        results into the same {"incident": ..., "alerts": [...]} payload
        shape as the disk-cache path above."""
        monkeypatch.setenv("NW_HOST", "https://192.168.20.11")
        monkeypatch.setenv("NW_USERNAME", "admin")
        monkeypatch.setenv("NW_PASSWORD", "secret")

        with patch("APIRetrieval.fetch_incident_via_fetch_api", return_value={"id": "INC-LIVE-1", "title": "Live Test"}), \
             patch("APIRetrieval.fetch_alerts_via_fetch_api", return_value=[{"id": "ALERT-LIVE"}]), \
             patch("APIRetrieval.get_auth_token", return_value="TOKEN_LIVE"):

            payload = APIRetrieval.get_comprehensive_incident_payload("INC-LIVE-1")
            assert payload["incident"]["id"] == "INC-LIVE-1"
            assert len(payload["alerts"]) == 1
