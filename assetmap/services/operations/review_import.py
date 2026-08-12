from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlmodel import Session, select

from assetmap.models import ScanTask, SourceRawRecord


REVIEW_SOURCE = "review_workorder"
REVIEW_ACTION = "review_attestation"
PENDING_STATUSES = {"", "pending", "todo", "待确认", "待复核", "未复核"}


@dataclass
class ReviewImportResult:
    imported: int = 0
    skipped_pending: int = 0
    skipped_invalid: int = 0
    categories: dict[str, int] = field(default_factory=dict)


class ReviewImportService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def run(self, task_id: int, file_path: Path | str) -> ReviewImportResult:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        data = yaml.safe_load(Path(file_path).read_text(encoding="utf-8")) or {}
        items = data.get("review_items") or {}
        if not isinstance(items, dict):
            raise ValueError("review_items must be a mapping")

        result = ReviewImportResult()
        for category, rows in items.items():
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    result.skipped_invalid += 1
                    continue
                status = _review_status(row)
                if status.lower() in PENDING_STATUSES or status in PENDING_STATUSES:
                    result.skipped_pending += 1
                    continue
                item_key = _review_key(category, row)
                if not item_key:
                    result.skipped_invalid += 1
                    continue
                self._upsert(task.id, category, item_key, status, row)
                result.imported += 1
                result.categories[category] = result.categories.get(category, 0) + 1
        self.session.commit()
        return result

    def _upsert(self, task_id: int, category: str, item_key: str, status: str, row: dict[str, Any]) -> None:
        parameter_hash = hashlib.sha256(
            json.dumps(
                {"task_id": task_id, "category": category, "item_key": item_key},
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        payload = {
            "category": category,
            "item_key": item_key,
            "unit": item_key if category == "asset_supplement" else "",
            "review_status": status,
            "review_notes": _text(row.get("review_notes") or row.get("notes") or row.get("备注")),
            "reviewer": _text(row.get("reviewer") or row.get("复核人")),
            "reviewed_at": _text(row.get("reviewed_at") or row.get("复核时间")),
            "source_urls": _items(row.get("source_urls") or row.get("来源链接")),
            "confirmed_system_name": _text(row.get("confirmed_system_name") or row.get("确认系统名称")),
            "confirmed_site_purpose": _text(row.get("confirmed_site_purpose") or row.get("确认网站用途")),
            "confirmed_owner_unit": _text(row.get("confirmed_owner_unit") or row.get("确认归属单位")),
            "confirmed_page_type": _text(row.get("confirmed_page_type") or row.get("确认页面类型")),
            "confirmed_login_features": _text(row.get("confirmed_login_features") or row.get("确认登录特征")),
            "confirmed_business_functions": _text(row.get("confirmed_business_functions") or row.get("确认业务功能")),
            "raw": row,
        }
        existing = self.session.exec(
            select(SourceRawRecord).where(
                SourceRawRecord.task_id == task_id,
                SourceRawRecord.source == REVIEW_SOURCE,
                SourceRawRecord.action == REVIEW_ACTION,
                SourceRawRecord.parameter_hash == parameter_hash,
            )
        ).first()
        if existing:
            existing.response_json = payload
        else:
            existing = SourceRawRecord(
                task_id=task_id,
                source=REVIEW_SOURCE,
                action=REVIEW_ACTION,
                parameter_hash=parameter_hash,
                request_payload={"category": category, "item_key": item_key},
                response_json=payload,
            )
        self.session.add(existing)


def _review_status(row: dict[str, Any]) -> str:
    return _text(row.get("review_status") or row.get("status") or row.get("复核状态")).strip()


def _review_key(category: str, row: dict[str, Any]) -> str:
    if category == "asset_supplement":
        return _text(row.get("unit") or row.get("单位")).strip()
    if category == "dns":
        return _text(row.get("root_domain") or row.get("根域名")).lower().rstrip(".")
    if category == "service_classification":
        return _text(row.get("endpoint") or f"{row.get('IP') or ''}:{row.get('端口') or ''}").strip()
    if category == "url_entrypoint":
        return _text(row.get("url_sample") or row.get("url") or row.get("URL") or row.get("endpoint")).strip()
    if category == "visual_identification":
        return _text(row.get("url") or row.get("URL")).strip()
    return ""


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(item) for item in value if _text(item))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _items(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]
