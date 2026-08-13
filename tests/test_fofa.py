from __future__ import annotations

from assetmap.config import FofaConfig
from assetmap.services.mapping.fofa import FofaClient


def test_fofa_retries_429_without_exposing_request_url_or_key(monkeypatch):
    config = FofaConfig(email="user@example.test", api_key="secret-value")
    client = FofaClient(config)
    client._wait_for_request_slot = lambda: None  # type: ignore[method-assign]
    logs: list[str] = []
    client.set_progress(logs.append)
    sleeps: list[float] = []
    monkeypatch.setattr("assetmap.services.mapping.fofa.time.sleep", sleeps.append)

    class FakeResponse:
        def __init__(self, status_code: int, payload=None):
            self.status_code = status_code
            self.headers = {}
            self._payload = payload or {}

        def json(self):
            return self._payload

    responses = iter(
        [
            FakeResponse(429),
            FakeResponse(200, {"results": [["https://example.test", "8.8.8.8", 443, "https", "Portal", "nginx"]]}),
        ]
    )

    class FakeHttpClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, *args, **kwargs):
            return next(responses)

    monkeypatch.setattr("assetmap.services.mapping.fofa.httpx.Client", FakeHttpClient)

    ports = client.search_ip_ports("8.8.8.8")

    assert [(item.ip, item.port) for item in ports] == [("8.8.8.8", 443)]
    assert sleeps == [3]
    assert any("rate limited" in message for message in logs)
    assert all("secret-value" not in message and "http" not in message for message in logs)


def test_fofa_http_failures_are_sanitized(monkeypatch):
    client = FofaClient(FofaConfig(email="user@example.test", api_key="secret-value"))
    client._wait_for_request_slot = lambda: None  # type: ignore[method-assign]

    class FakeResponse:
        status_code = 400
        headers = {}

    class FakeHttpClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("assetmap.services.mapping.fofa.httpx.Client", FakeHttpClient)

    try:
        client.search_ip_ports("8.8.8.8")
    except RuntimeError as exc:
        assert str(exc) == "FOFA HTTP 400; request URL and credentials were redacted."
    else:
        raise AssertionError("expected an HTTP failure")
