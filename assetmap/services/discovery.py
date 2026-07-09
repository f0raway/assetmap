from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig
from assetmap.models import Company, CompanyAssetLink, CompanyEdge, InternetAsset, ScanTask, SourceRawRecord
from assetmap.services.maintenance import MaintenanceService
from assetmap.utils import extract_percent, normalize_company_name, normalize_uscc, stable_hash


@dataclass
class DiscoveryResult:
    task_id: int
    company_count: int
    asset_count: int
    asset_counts: dict[str, int] | None = None


ASSET_TYPES = {
    "domain": "icp_domain",
    "icp_domain": "icp_domain",
    "app": "app",
    "email": "email",
    "wechat": "wechat_official_account",
    "wechat_service": "wechat_service_account",
    "wechat_service_account": "wechat_service_account",
    "wechat_official_account": "wechat_official_account",
    "mini_program": "mini_program",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _redact_command(command: list[str]) -> list[str]:
    redacted = list(command)
    for option in ("--tycid", "--auth-token"):
        if option in redacted:
            index = redacted.index(option)
            if index + 1 < len(redacted):
                redacted[index + 1] = "***"
    return redacted


def _company_payload(record: dict[str, Any]) -> dict[str, Any]:
    basic = record.get("basic") if isinstance(record.get("basic"), dict) else {}
    name = _text(record.get("name") or basic.get("name")) or "未知企业"
    return {
        "name": name,
        "normalized_name": normalize_company_name(name),
        "uscc": normalize_uscc(_text(basic.get("credit_code") or basic.get("creditCode"))),
        "registration_status": _text(basic.get("reg_status")),
        "legal_representative": _text(basic.get("legal_person")),
        "area": _text(basic.get("address")),
        "industry": _text(basic.get("industry")),
        "raw_payload": record,
        "updated_at": _utcnow(),
    }


def _asset_payload(record: dict[str, Any]) -> tuple[str, str, str] | None:
    source_type = _text(record.get("asset_type")).lower()
    asset_type = ASSET_TYPES.get(source_type)
    identifier = _normalize_asset_identifier(asset_type or "", record)
    if not asset_type or not identifier:
        return None
    display_name = _text(record.get("name") or record.get("identifier"))
    if not display_name:
        display_name = identifier
    return asset_type, identifier, display_name


def _normalize_asset_identifier(asset_type: str, record: dict[str, Any]) -> str:
    identifier = _text(record.get("identifier") or record.get("name"))
    if asset_type == "icp_domain":
        identifier = identifier or _first_url_host(record.get("url"))
        identifier = re.sub(r"^https?://", "", identifier.strip(), flags=re.I)
        identifier = identifier.split("/")[0].split(":")[0].lower().rstrip(".")
        if identifier.startswith("*."):
            identifier = identifier[2:]
        return identifier
    if asset_type == "email":
        return identifier.lower()
    if asset_type == "mini_program":
        return _normalize_named_asset_identifier(
            record,
            preferred_keys=("appid", "app_id", "filing_number", "identifier", "name"),
            numeric_identifier_fallback="filing_number",
        )
    if asset_type in {"wechat_official_account", "wechat_service_account"}:
        return _normalize_named_asset_identifier(
            record,
            preferred_keys=("account", "ghid", "identifier", "name", "filing_number"),
        )
    if asset_type == "app":
        return _normalize_named_asset_identifier(
            record,
            preferred_keys=("package", "bundle", "appid", "app_id", "identifier", "filing_number", "name"),
            lowercase_ascii_package=True,
        )
    return identifier.lower()


def _normalize_named_asset_identifier(
    record: dict[str, Any],
    *,
    preferred_keys: tuple[str, ...],
    numeric_identifier_fallback: str | None = None,
    lowercase_ascii_package: bool = False,
) -> str:
    identifier = _text(record.get("identifier"))
    if numeric_identifier_fallback and identifier.isdigit() and _text(record.get(numeric_identifier_fallback)):
        identifier = ""
    value = ""
    for key in preferred_keys:
        candidate = identifier if key == "identifier" else _text(record.get(key))
        if candidate:
            value = candidate
            break
    value = re.sub(r"\s+", "", value)
    if lowercase_ascii_package and "." in value and re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        return value.lower()
    return value


def _first_url_host(value: Any) -> str:
    text = _text(value).strip("[]'\" ")
    if not text:
        return ""
    first = text.split(",", 1)[0].strip(" '\"")
    return first


class DiscoveryService:
    def __init__(
        self,
        session: Session,
        config: AppConfig,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.session = session
        self.config = config
        self.progress = progress

    def _log(self, message: str) -> None:
        if self.progress:
            try:
                self.progress(message)
            except OSError:
                self.progress = None

    def run(self, target: str | None, resume_task_id: int | None = None, fresh: bool = False) -> DiscoveryResult:
        task = self._start_task(target, resume_task_id, refresh=fresh)
        target = task.target
        self._log(f"[task {task.id}] start ENScan discovery: {target}")
        try:
            payload = self._run_collector(task.id, target, fresh=fresh)
            self._record_raw(task.id, "result", {"target": target}, payload)
            self._save_result(task.id, payload)
            self._log_payload_quality(task.id, payload)
            task.status = "completed"
            task.finished_at = _utcnow()
        except KeyboardInterrupt:
            task.status = "interrupted"
            task.finished_at = _utcnow()
            task.error_message = "Interrupted by user"
            raise
        except Exception as exc:
            task.status = "failed"
            task.finished_at = _utcnow()
            task.error_message = str(exc)
            self._log(f"[task {task.id}] failed: {exc}")
            raise
        finally:
            self.session.add(task)
            self.session.commit()

        company_count = self._company_count(task.id)
        asset_counts = self._asset_counts(task.id)
        asset_count = sum(asset_counts.values())
        self._log(f"[task {task.id}] completed: companies={company_count}, assets={asset_count}")
        if asset_counts:
            summary = ", ".join(f"{asset_type}={count}" for asset_type, count in sorted(asset_counts.items()))
            self._log(f"[task {task.id}] asset summary: {summary}")
        return DiscoveryResult(task.id, company_count, asset_count, asset_counts)

    def _start_task(self, target: str | None, resume_task_id: int | None, refresh: bool = False) -> ScanTask:
        if resume_task_id is not None:
            task = self.session.get(ScanTask, resume_task_id)
            if not task:
                raise ValueError(f"Scan task not found: {resume_task_id}")
            if target and target != task.target:
                raise ValueError(f"Resume task {resume_task_id} target is {task.target!r}, not {target!r}.")
            task.status = "running"
            task.error_message = None
            task.finished_at = None
        else:
            if not target:
                raise ValueError("Target is required unless --resume-task is used.")

            latest_task = None if refresh else self._latest_task_for_target(target)
            if latest_task and latest_task.status != "completed":
                task = latest_task
                task.status = "running"
                task.error_message = None
                task.finished_at = None
                self._log(f"[task] resume interrupted task_{task.id}")
            else:
                # 已完成任务进入增量积累模式：创建新任务并继承历史数据。
                previous_task = latest_task if latest_task and latest_task.status == "completed" else None

                if previous_task:
                    self._log(f"[task] 检测到历史任务 task_{previous_task.id} ({previous_task.finished_at.strftime('%Y-%m-%d') if previous_task.finished_at else 'unknown'} 完成)")

                    task = ScanTask(target=target, status="running")
                    self.session.add(task)
                    self.session.commit()
                    self.session.refresh(task)

                    inherited = self._inherit_historical_data(previous_task.id, task.id)
                    self._log(f"[task] 继承历史数据: {inherited['companies']} 公司, {inherited['edges']} 股权关系, {inherited['assets']} 资产")
                else:
                    # 全新任务
                    task = ScanTask(target=target, status="running")

        self.session.add(task)
        self.session.commit()
        self.session.refresh(task)
        return task

    def _latest_completed_task_for_target(self, target: str) -> ScanTask | None:
        """查找同名目标最近一次已完成的任务"""
        return self.session.exec(
            select(ScanTask)
            .where(
                ScanTask.target == target,
                ScanTask.status == "completed",
            )
            .order_by(ScanTask.finished_at.desc())
        ).first()

    def _inherit_historical_data(self, from_task_id: int, to_task_id: int) -> dict[str, int]:
        """从历史任务继承数据到新任务"""
        inherited = {"companies": 0, "edges": 0, "assets": 0}

        # 1. 继承公司股权关系（CompanyEdge）
        old_edges = self.session.exec(
            select(CompanyEdge).where(CompanyEdge.task_id == from_task_id)
        ).all()

        for old_edge in old_edges:
            new_edge = CompanyEdge(
                task_id=to_task_id,
                parent_company_id=old_edge.parent_company_id,
                child_company_id=old_edge.child_company_id,
                direct_holding_ratio=old_edge.direct_holding_ratio,
                cumulative_holding_ratio=old_edge.cumulative_holding_ratio,
                depth=old_edge.depth,
                path=old_edge.path,
            )
            self.session.add(new_edge)
            inherited["edges"] += 1

        # 2. 继承资产关联（CompanyAssetLink）
        old_links = self.session.exec(
            select(CompanyAssetLink).where(CompanyAssetLink.task_id == from_task_id)
        ).all()

        for old_link in old_links:
            new_link = CompanyAssetLink(
                task_id=to_task_id,
                company_id=old_link.company_id,
                asset_id=old_link.asset_id,
                source_tool=old_link.source_tool,
                raw_payload=old_link.raw_payload,
            )
            self.session.add(new_link)
            inherited["assets"] += 1

        # 3. 统计继承的公司数量
        company_ids = set()
        for edge in old_edges:
            company_ids.add(edge.parent_company_id)
            company_ids.add(edge.child_company_id)
        for link in old_links:
            company_ids.add(link.company_id)
        inherited["companies"] = len(company_ids)

        self.session.commit()
        return inherited

    def _latest_task_for_target(self, target: str) -> ScanTask | None:
        return self.session.exec(
            select(ScanTask)
            .where(ScanTask.target == target)
            .order_by(ScanTask.id.desc())
        ).first()

    def _run_collector(self, task_id: int, target: str, fresh: bool = False) -> dict[str, Any]:
        output_path = (Path(self.config.enscan.output_dir) / f"task_{task_id}.json").resolve()
        csv_dir = output_path.with_suffix("")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tycid = self.config.enscan.tycid.strip()
        auth_token = self.config.enscan.auth_token.strip()
        command = [
            sys.executable,
            str(Path(self.config.enscan.script)),
            "--name",
            target,
            "--tycid",
            tycid,
            "--auth-token",
            auth_token,
            "--output",
            str(output_path),
            "--csv-dir",
            str(csv_dir),
            "--max-depth",
            str(self.config.org.max_depth),
            "--threshold",
            str(self.config.org.control_threshold * 100),
            "--delay",
            str(self.config.enscan.request_delay_seconds),
            "--timeout",
            str(self.config.enscan.request_timeout_seconds),
            "--asset-workers",
            str(self.config.enscan.asset_workers),
        ]
        if fresh:
            command.append("--fresh")
        if self.config.enscan.verbose:
            command.append("--verbose")
        if tycid.startswith("YOUR_") or auth_token.startswith("YOUR_"):
            raise ValueError("Please set enscan.tycid and enscan.auth_token in config.yaml before running discover.")
        safe_command = _redact_command(command)
        self._log(f"[enscan] running: {' '.join(safe_command)}")
        returncode, output_tail = self._run_process_streaming(command)
        self._record_raw(
            task_id,
            "process",
            {"command": safe_command, "output": str(output_path)},
            {
                "returncode": returncode,
                "stdout": output_tail,
                "stderr": "",
            },
        )
        if returncode != 0:
            detail = output_tail.strip()
            raise RuntimeError(f"ENScan failed with exit code {returncode}: {detail[-1000:]}")
        return json.loads(output_path.read_text(encoding="utf-8"))

    def _run_process_streaming(self, command: list[str]) -> tuple[int, str]:
        started_at = time.monotonic()
        lines: deque[str] = deque(maxlen=800)
        timed_out = False

        def kill_on_timeout() -> None:
            nonlocal timed_out
            if proc.poll() is None:
                timed_out = True
                proc.kill()

        proc = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        timer = threading.Timer(self.config.enscan.timeout_seconds, kill_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                lines.append(line)
                self._log(line.rstrip())
            returncode = proc.wait()
            output_tail = "".join(lines)[-20000:]
            if timed_out:
                elapsed = int(time.monotonic() - started_at)
                raise TimeoutError(f"ENScan timed out after {elapsed}s")
            return returncode, output_tail
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        finally:
            timer.cancel()

    def _save_result(self, task_id: int, payload: dict[str, Any]) -> None:
        self._clear_source_links(task_id, "enscan_python")
        self._clear_edges(task_id)
        companies = self._save_companies(payload.get("companies") or [])
        for record in payload.get("companies") or []:
            company = companies.get(_text(record.get("pid")))
            if company:
                self._save_assets(task_id, company, record.get("digital_assets") or [])
        for edge in payload.get("edges") or []:
            self._save_edge(task_id, edge, companies)
        self._refresh_edge_paths(task_id)
        MaintenanceService(self.session).dedupe_asset_links(task_id)

    def _clear_source_links(self, task_id: int, source_tool: str) -> int:
        links = self.session.exec(
            select(CompanyAssetLink).where(
                CompanyAssetLink.task_id == task_id,
                CompanyAssetLink.source_tool == source_tool,
            )
        ).all()
        removed = 0
        for link in links:
            payload = {**(link.raw_payload or {})}
            sources = set(payload.get("sources") or [link.source_tool])
            if sources - {source_tool}:
                fallback_source = sorted(sources - {source_tool})[0]
                existing = self.session.exec(
                    select(CompanyAssetLink).where(
                        CompanyAssetLink.task_id == task_id,
                        CompanyAssetLink.company_id == link.company_id,
                        CompanyAssetLink.asset_id == link.asset_id,
                        CompanyAssetLink.source_tool == fallback_source,
                        CompanyAssetLink.id != link.id,
                    )
                ).first()
                if existing:
                    self.session.delete(link)
                    removed += 1
                    continue
                link.source_tool = fallback_source
                payload["sources"] = sorted(sources - {source_tool})
                payload["evidence"] = [
                    item
                    for item in payload.get("evidence", [])
                    if isinstance(item, dict) and item.get("source") != source_tool
                ]
                link.raw_payload = payload
                self.session.add(link)
                continue
            self.session.delete(link)
            removed += 1
        if links:
            self.session.commit()
        return removed

    def _clear_edges(self, task_id: int) -> int:
        edges = self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        for edge in edges:
            self.session.delete(edge)
        if edges:
            self.session.commit()
        return len(edges)

    def _save_companies(self, records: list[dict[str, Any]]) -> dict[str, Company]:
        companies: dict[str, Company] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            company = self._upsert_company(_company_payload(record))
            pid = _text(record.get("pid"))
            if pid:
                companies[pid] = company
            self.session.commit()
        return companies

    def _upsert_company(self, data: dict[str, Any]) -> Company:
        statement = (
            select(Company).where(Company.uscc == data["uscc"])
            if data.get("uscc")
            else select(Company).where(Company.normalized_name == data["normalized_name"])
        )
        company = self.session.exec(statement).first()
        if not company:
            company = Company(created_at=_utcnow(), **data)
        else:
            for key, value in data.items():
                if value is not None:
                    setattr(company, key, value)
        self.session.add(company)
        self.session.flush()
        return company

    def _save_assets(self, task_id: int, company: Company, records: list[dict[str, Any]]) -> None:
        for record in records:
            if not isinstance(record, dict):
                continue
            parsed = _asset_payload(record)
            if not parsed:
                continue
            asset_type, identifier, display_name = parsed
            asset = self._upsert_asset(asset_type, identifier, display_name, record)
            self._link_asset(task_id, company, asset, record)

    def _upsert_asset(self, asset_type: str, identifier: str, display_name: str, raw_payload: dict[str, Any]) -> InternetAsset:
        asset = self.session.exec(
            select(InternetAsset).where(
                InternetAsset.asset_type == asset_type,
                InternetAsset.normalized_identifier == identifier,
            )
        ).first()
        if not asset:
            asset = InternetAsset(asset_type=asset_type, normalized_identifier=identifier, display_name=display_name, raw_payload=raw_payload)
        else:
            asset.display_name = display_name
            asset.raw_payload = raw_payload
            asset.updated_at = _utcnow()
        self.session.add(asset)
        self.session.flush()
        return asset

    def _link_asset(self, task_id: int, company: Company, asset: InternetAsset, raw_payload: dict[str, Any]) -> None:
        exists = self.session.exec(
            select(CompanyAssetLink).where(
                CompanyAssetLink.task_id == task_id,
                CompanyAssetLink.company_id == company.id,
                CompanyAssetLink.asset_id == asset.id,
            )
        ).first()
        if exists:
            payload = {**(exists.raw_payload or {})}
            sources = list(payload.get("sources") or [exists.source_tool])
            if "enscan_python" not in sources:
                payload["sources"] = [*sources, "enscan_python"]
                payload["evidence"] = [
                    *list(payload.get("evidence") or [{"source": exists.source_tool, "raw": exists.raw_payload}]),
                    {"source": "enscan_python", "raw": raw_payload},
                ]
                exists.raw_payload = payload
                self.session.add(exists)
                self.session.commit()
            return
        self.session.add(
            CompanyAssetLink(
                task_id=task_id,
                company_id=company.id,
                asset_id=asset.id,
                source_tool="enscan_python",
                raw_payload=raw_payload,
            )
        )
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()

    def _save_edge(self, task_id: int, record: dict[str, Any], companies: dict[str, Company]) -> None:
        ratio = extract_percent(record.get("percent_value") or record.get("percent"))
        parent = companies.get(_text(record.get("from_pid")))
        child = companies.get(_text(record.get("to_pid")))
        if not parent or not child or ratio is None or ratio <= self.config.org.control_threshold:
            return
        exists = self.session.exec(
            select(CompanyEdge).where(
                CompanyEdge.task_id == task_id,
                CompanyEdge.parent_company_id == parent.id,
                CompanyEdge.child_company_id == child.id,
            )
        ).first()
        if exists:
            exists.direct_holding_ratio = ratio
            exists.depth = int(record.get("depth") or exists.depth or 1)
            self.session.add(exists)
            self.session.commit()
            return
        self.session.add(
            CompanyEdge(
                task_id=task_id,
                parent_company_id=parent.id,
                child_company_id=child.id,
                direct_holding_ratio=ratio,
                cumulative_holding_ratio=ratio,
                depth=int(record.get("depth") or 1),
                path=f"{parent.name} > {child.name}",
            )
        )
        self.session.commit()

    def _refresh_edge_paths(self, task_id: int) -> None:
        edges = self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        if not edges:
            return
        company_ids = {edge.parent_company_id for edge in edges} | {edge.child_company_id for edge in edges}
        companies = {
            company.id: company
            for company in self.session.exec(select(Company).where(Company.id.in_(company_ids))).all()
        }
        children: dict[int, list[CompanyEdge]] = defaultdict(list)
        child_ids = set()
        for edge in edges:
            children[edge.parent_company_id].append(edge)
            child_ids.add(edge.child_company_id)
        roots = [company_id for company_id in children if company_id not in child_ids] or list(children)
        best_cumulative: dict[int, float] = {}
        visited_edges: set[int] = set()

        def walk(company_id: int, cumulative: float, path: str, depth: int) -> None:
            previous = best_cumulative.get(company_id)
            if previous is not None and previous >= cumulative:
                return
            best_cumulative[company_id] = cumulative
            for edge in sorted(children.get(company_id, []), key=lambda item: (item.depth, item.child_company_id)):
                child = companies.get(edge.child_company_id)
                child_name = child.name if child else str(edge.child_company_id)
                edge.depth = depth + 1
                edge.cumulative_holding_ratio = cumulative * edge.direct_holding_ratio
                edge.path = f"{path} > {child_name}" if path else child_name
                visited_edges.add(edge.id or 0)
                self.session.add(edge)
                walk(edge.child_company_id, edge.cumulative_holding_ratio, edge.path, edge.depth)

        for root_id in roots:
            root = companies.get(root_id)
            walk(root_id, 1.0, root.name if root else str(root_id), 0)
        for edge in edges:
            if edge.id not in visited_edges:
                parent = companies.get(edge.parent_company_id)
                child = companies.get(edge.child_company_id)
                edge.cumulative_holding_ratio = edge.direct_holding_ratio
                edge.path = f"{parent.name if parent else edge.parent_company_id} > {child.name if child else edge.child_company_id}"
                self.session.add(edge)
        self.session.commit()

    def _record_raw(self, task_id: int, action: str, request: dict[str, Any], response: dict[str, Any]) -> None:
        self.session.add(
            SourceRawRecord(
                task_id=task_id,
                source="enscan_python",
                action=action,
                parameter_hash=stable_hash(request),
                request_payload=request,
                response_json=response,
            )
        )
        self.session.commit()

    def _company_count(self, task_id: int) -> int:
        edges = self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        links = self.session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        return len({edge.parent_company_id for edge in edges} | {edge.child_company_id for edge in edges} | {link.company_id for link in links})

    def _asset_counts(self, task_id: int) -> dict[str, int]:
        links = self.session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        asset_ids = {link.asset_id for link in links}
        if not asset_ids:
            return {}
        assets = self.session.exec(select(InternetAsset).where(InternetAsset.id.in_(asset_ids))).all()
        return dict(Counter(asset.asset_type for asset in assets))

    def _log_payload_quality(self, task_id: int, payload: dict[str, Any]) -> None:
        companies = payload.get("companies") or []
        edges = payload.get("edges") or []
        digital_assets = [
            asset
            for company in companies
            if isinstance(company, dict)
            for asset in (company.get("digital_assets") or [])
            if isinstance(asset, dict)
        ]
        self._log(
            f"[task {task_id}] collector payload: companies={len(companies)}, "
            f"edges={len(edges)}, digital_assets={len(digital_assets)}"
        )
        if not companies:
            self._log(f"[task {task_id}] warning: collector returned no companies")
        if companies and not digital_assets:
            self._log(f"[task {task_id}] warning: collector returned companies but no digital assets")
