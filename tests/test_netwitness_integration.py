from __future__ import annotations

import pytest
import requests

from integrations.netwitness import NetWitnessClient, NetWitnessConfig, NetWitnessError


class Response:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def config(**values):
    defaults = {"base_url": "https://nw.example", "token": "secret-token", "verify_tls": True}
    defaults.update(values)
    return NetWitnessConfig(**defaults)


def test_successful_authentication_and_token_verification():
    session = Session([
        Response(payload={"accessToken": "new-secret"}),
        Response(payload={"items": [], "hasNext": False}),
    ])
    client = NetWitnessClient(config(token="", username="analyst", password="password"), session)
    client.login()
    assert client.config.token == "new-secret"
    assert client.verify_token() is True
    assert session.calls[0][2]["verify"] is True


def test_failed_authentication_has_safe_error():
    client = NetWitnessClient(config(token="", username="analyst", password="password"), Session([Response(401, {})]))
    with pytest.raises(NetWitnessError) as caught:
        client.login()
    assert caught.value.code == "NETWITNESS_AUTH_FAILED"
    assert "password" not in caught.value.message


def test_invalid_token():
    client = NetWitnessClient(config(), Session([Response(401, {})]))
    with pytest.raises(NetWitnessError) as caught:
        client.verify_token()
    assert caught.value.code == "NETWITNESS_TOKEN_INVALID"


@pytest.mark.parametrize("failure,code", [
    (requests.exceptions.ConnectionError(), "NETWITNESS_UNREACHABLE"),
    (requests.exceptions.SSLError(), "NETWITNESS_TLS_ERROR"),
])
def test_connectivity_failures_are_classified(failure, code):
    client = NetWitnessClient(config(), Session([failure]))
    with pytest.raises(NetWitnessError) as caught:
        client.verify_token()
    assert caught.value.code == code


def test_incident_retrieval_preserves_remote_schema():
    incident = {"id": "INC-1", "riskScore": 80, "status": "OPEN"}
    client = NetWitnessClient(config(), Session([Response(payload={
        "items": [incident], "hasNext": False, "totalItems": 1,
    })]))
    result = client.get_incidents(limit=25)
    assert result["items"] == [incident]
    assert result["total"] == 1


def test_malformed_incident_response():
    client = NetWitnessClient(config(), Session([Response(payload={"results": []})]))
    with pytest.raises(NetWitnessError) as caught:
        client.get_incidents()
    assert caught.value.code == "NETWITNESS_RESPONSE_INVALID"


def test_alert_and_detail_retrieval_with_identity_guards():
    session = Session([
        Response(payload={"items": [{"id": "A-1"}], "hasNext": False}),
        Response(payload={"id": "A-1", "name": "Alert"}),
    ])
    client = NetWitnessClient(config(), session)
    assert client.get_alerts("INC/1") == [{"id": "A-1", "incident_id": "INC/1"}]
    assert client.get_alert_details("A-1")["name"] == "Alert"
    assert "/INC%2F1/alerts" in session.calls[0][1]


def test_expired_token_reauthenticates_once():
    session = Session([
        Response(401, {}),
        Response(payload={"accessToken": "refreshed"}),
        Response(payload={"items": [], "hasNext": False}),
    ])
    client = NetWitnessClient(config(username="analyst", password="password"), session)
    assert client.verify_token() is True
    assert client.config.token == "refreshed"


def test_insecure_tls_is_explicit_and_centralized():
    session = Session([Response(payload={"items": [], "hasNext": False})])
    client = NetWitnessClient(config(verify_tls=False), session)
    client.verify_token()
    assert session.calls[0][2]["verify"] is False
