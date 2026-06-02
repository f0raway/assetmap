from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


USCC_PATTERN = re.compile(r"^[0-9A-Z]{18}$")


def normalize_company_name(value: str) -> str:
    return re.sub(r"\s+", "", value or "").strip().lower()


def normalize_uscc(value: str | None) -> str | None:
    if not value:
        return None
    normalized = re.sub(r"\s+", "", value).upper()
    return normalized if USCC_PATTERN.fullmatch(normalized) else None


def is_probably_uscc(value: str) -> bool:
    return normalize_uscc(value) is not None


def extract_percent(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric / 100 if numeric > 1 else numeric
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if not match:
        return None
    numeric = float(match.group(1))
    return numeric / 100 if "%" in text or numeric > 1 else numeric


def stable_hash(payload: dict) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def iter_records(payload: Any) -> Iterable[dict]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items", "list", "records", "result", "对外投资信息"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []
