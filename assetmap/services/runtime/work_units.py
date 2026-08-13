from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from assetmap.models import StageWorkUnit


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WorkUnitTracker:
    """Shared persistence rules for independently resumable stage work."""

    def __init__(self, session: Session, scan_task_id: int, stage: str) -> None:
        self.session = session
        self.scan_task_id = scan_task_id
        self.stage = stage

    @staticmethod
    def fingerprint(payload: dict[str, Any]) -> str:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def get_or_create(
        self,
        unit_type: str,
        unit_key: str,
        input_payload: dict[str, Any],
    ) -> tuple[StageWorkUnit, bool]:
        """Return the unit and whether its input changed since a completed run.

        A changed completed unit is deliberately *not* reset.  Callers can show
        that it is stale and require an explicit rerun instead of silently
        repeating network activity.
        """
        fingerprint = self.fingerprint(input_payload)
        unit = self.session.exec(
            select(StageWorkUnit).where(
                StageWorkUnit.scan_task_id == self.scan_task_id,
                StageWorkUnit.stage == self.stage,
                StageWorkUnit.unit_type == unit_type,
                StageWorkUnit.unit_key == unit_key,
            )
        ).first()
        if unit:
            return unit, unit.input_fingerprint != fingerprint
        unit = StageWorkUnit(
            scan_task_id=self.scan_task_id,
            stage=self.stage,
            unit_type=unit_type,
            unit_key=unit_key,
            input_fingerprint=fingerprint,
        )
        self.session.add(unit)
        self.session.commit()
        self.session.refresh(unit)
        return unit, False

    def begin(self, unit: StageWorkUnit) -> None:
        unit.status = "running"
        unit.attempts += 1
        unit.started_at = _utcnow()
        unit.finished_at = None
        unit.error_message = None
        self.session.add(unit)
        self.session.commit()

    def complete(
        self,
        unit: StageWorkUnit,
        *,
        output_path: str | Path | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        unit.status = "completed"
        unit.finished_at = _utcnow()
        if output_path is not None:
            unit.output_path = str(output_path)
        if details is not None:
            unit.details = details
        unit.error_message = None
        self.session.add(unit)
        self.session.commit()

    def fail(self, unit: StageWorkUnit, message: str, *, interrupted: bool = False) -> None:
        unit.status = "interrupted" if interrupted else "failed"
        unit.finished_at = _utcnow()
        unit.error_message = message[:1000]
        self.session.add(unit)
        self.session.commit()

    @staticmethod
    def completed_output_exists(unit: StageWorkUnit) -> bool:
        return unit.status == "completed" and (not unit.output_path or Path(unit.output_path).exists())
