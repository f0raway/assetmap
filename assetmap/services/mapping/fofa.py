from __future__ import annotations

import base64
from dataclasses import dataclass
import time
from typing import Any, Callable

import httpx

from assetmap.config import FofaConfig


FOFA_BASE_URL = "https://fofa.info"
FOFA_FIELDS = "host,ip,port,protocol,title,server"
FOFA_SIZE = 1000
FOFA_TIMEOUT_SECONDS = 30
FOFA_REQUEST_INTERVAL_SECONDS = 2.0
FOFA_MAX_RATE_LIMIT_RETRIES = 3
FOFA_RATE_LIMIT_BACKOFF_SECONDS = (3, 6, 12)


@dataclass
class FofaPort:
    ip: str
    port: int
    protocol: str
    host: str = ""
    title: str = ""
    server: str = ""
    raw: dict[str, Any] | None = None


class FofaClient:
    def __init__(self, config: FofaConfig) -> None:
        self.config = config
        self._progress: Callable[[str], None] | None = None
        self._last_request_at: float | None = None

    def set_progress(self, progress: Callable[[str], None] | None) -> None:
        """Attach a safe user-facing progress callback after construction."""
        self._progress = progress

    def _log(self, message: str) -> None:
        if self._progress:
            self._progress(message)

    def _wait_for_request_slot(self) -> None:
        if self._last_request_at is None:
            return
        remaining = FOFA_REQUEST_INTERVAL_SECONDS - (time.monotonic() - self._last_request_at)
        if remaining > 0:
            time.sleep(remaining)

    def search_ip_ports(self, ip: str) -> list[FofaPort]:
        if self.config.email.startswith("YOUR_") or self.config.api_key.startswith("YOUR_"):
            raise ValueError("Please set fofa.email and fofa.api_key in config.yaml before running port scan.")
        fields = [field.strip() for field in FOFA_FIELDS.split(",") if field.strip()]
        query = f'ip="{ip}"'
        params = {
            "email": self.config.email,
            "key": self.config.api_key,
            "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
            "fields": ",".join(fields),
            "size": FOFA_SIZE,
            "full": "true",
        }
        payload: dict[str, Any] | None = None
        for attempt in range(FOFA_MAX_RATE_LIMIT_RETRIES + 1):
            self._wait_for_request_slot()
            with httpx.Client(base_url=FOFA_BASE_URL, timeout=FOFA_TIMEOUT_SECONDS, trust_env=False) as client:
                response = client.get("/api/v1/search/all", params=params)
            self._last_request_at = time.monotonic()
            if response.status_code == 429:
                if attempt >= FOFA_MAX_RATE_LIMIT_RETRIES:
                    raise RuntimeError("FOFA rate limit persisted after automatic retries; this target was recorded for a later retry.")
                delay = self._rate_limit_delay(response, attempt)
                self._log(
                    f"[fofa] rate limited; waiting {delay:g}s before retry "
                    f"({attempt + 1}/{FOFA_MAX_RATE_LIMIT_RETRIES})"
                )
                time.sleep(delay)
                continue
            if response.status_code >= 400:
                raise RuntimeError(f"FOFA HTTP {response.status_code}; request URL and credentials were redacted.")
            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError("FOFA returned invalid JSON; request URL and credentials were redacted.") from exc
            break
        if payload is None:
            raise RuntimeError("FOFA request did not return a result.")
        if payload.get("error"):
            message = str(payload.get("errmsg") or payload.get("message") or "FOFA rejected the query")
            raise RuntimeError(self._redact(message))
        return self._parse_results(payload, fields, ip)

    @staticmethod
    def _rate_limit_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After", "").strip()
        try:
            return max(1.0, min(float(retry_after), 60.0))
        except ValueError:
            return FOFA_RATE_LIMIT_BACKOFF_SECONDS[min(attempt, len(FOFA_RATE_LIMIT_BACKOFF_SECONDS) - 1)]

    def _redact(self, message: str) -> str:
        sanitized = message.replace(self.config.api_key, "[REDACTED_SECRET]")
        sanitized = sanitized.replace(self.config.email, "[REDACTED_EMAIL]")
        return sanitized[:500]

    def _parse_results(self, payload: dict[str, Any], fields: list[str], fallback_ip: str) -> list[FofaPort]:
        ports: list[FofaPort] = []
        for row in payload.get("results") or []:
            if isinstance(row, dict):
                item = row
            elif isinstance(row, list):
                item = {field: row[index] if index < len(row) else "" for index, field in enumerate(fields)}
            else:
                continue
            ip = str(item.get("ip") or fallback_ip).strip()
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not ip or port <= 0:
                continue
            protocol = str(item.get("protocol") or "").strip().lower() or "tcp"
            ports.append(
                FofaPort(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    host=str(item.get("host") or "").strip(),
                    title=str(item.get("title") or "").strip(),
                    server=str(item.get("server") or "").strip(),
                    raw=item,
                )
            )
        return ports
