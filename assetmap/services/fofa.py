from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from assetmap.config import FofaConfig


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

    def search_ip_ports(self, ip: str) -> list[FofaPort]:
        if self.config.email.startswith("YOUR_") or self.config.api_key.startswith("YOUR_"):
            raise ValueError("Please set fofa.email and fofa.api_key in config.yaml, or disable fofa in port_scan.sources_enabled.")
        fields = [field.strip() for field in self.config.fields.split(",") if field.strip()]
        query = f'ip="{ip}"'
        params = {
            "email": self.config.email,
            "key": self.config.api_key,
            "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
            "fields": ",".join(fields),
            "size": self.config.size,
            "full": "true" if self.config.full else "false",
        }
        with httpx.Client(base_url=self.config.base_url.rstrip("/"), timeout=self.config.timeout_seconds, trust_env=False) as client:
            response = client.get("/api/v1/search/all", params=params)
            response.raise_for_status()
            payload = response.json()
        if payload.get("error"):
            raise RuntimeError(str(payload.get("errmsg") or payload.get("message") or payload))
        return self._parse_results(payload, fields, ip)

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
