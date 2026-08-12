from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlmodel import Session, select

from assetmap.models import (
    AiAnalysis,
    AssetClassificationTask,
    Company,
    CompanyAssetLink,
    CompanyEdge,
    DnsQueryStatus,
    DnsRecord,
    InternetAsset,
    NmapPort,
    NmapScanRun,
    NmapScanTask,
    ReportGenerationTask,
    ScanTask,
    ServiceAsset,
    SubdomainEnumerationTask,
    SubdomainRecord,
    SubdomainToolRun,
    UrlDiscoveryTask,
    WebEntrypoint,
)


STALE_RUNNING_AFTER = timedelta(hours=2)


@dataclass
class PipelineStatus:
    task: ScanTask
    stages: list[tuple[str, str, str]]
    lines: list[str]
    next_step: str | None


class PipelineStatusService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, task_id: int) -> PipelineStatus:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        counts = self._counts(task_id)
        stages = self._stages(task_id, counts)
        lines = [
            f"Task: {task.id}",
            f"Target: {task.target}",
            f"Status: {task.status}",
            "",
            "Pipeline:",
        ]
        for name, status, detail in stages:
            lines.append(f"- {name}: {status} ({detail})")
        next_step = self._next_step(stages)
        return PipelineStatus(task=task, stages=stages, lines=lines, next_step=next_step)

    def _counts(self, task_id: int) -> dict[str, int]:
        company_ids = {
            row.parent_company_id
            for row in self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        } | {
            row.child_company_id
            for row in self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        } | {
            row.company_id
            for row in self.session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        }
        asset_ids = {
            row.asset_id
            for row in self.session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        }
        open_ports = self.session.exec(
            select(NmapPort).where(NmapPort.scan_task_id == task_id, NmapPort.state == "open")
        ).all()
        web_assets = self.session.exec(
            select(ServiceAsset).where(ServiceAsset.scan_task_id == task_id, ServiceAsset.asset_kind == "web")
        ).all()
        web_entrypoints = self.session.exec(
            select(WebEntrypoint).where(WebEntrypoint.scan_task_id == task_id)
        ).all()
        visual_done = [
            row for row in web_entrypoints if (row.evidence or {}).get("visual_analysis")
        ]
        visual_failed = [
            row
            for row in web_entrypoints
            if (row.evidence or {}).get("visual_analysis_error")
            and not (row.evidence or {}).get("visual_analysis")
        ]
        return {
            "companies": len(company_ids),
            "assets": len(asset_ids),
            "subdomains": len(self.session.exec(select(SubdomainRecord).where(SubdomainRecord.scan_task_id == task_id)).all()),
            "dns": len(self.session.exec(select(DnsRecord).where(DnsRecord.scan_task_id == task_id)).all()),
            "open_ports": len(open_ports),
            "service_assets": len(self.session.exec(select(ServiceAsset).where(ServiceAsset.scan_task_id == task_id)).all()),
            "web_assets": len(web_assets),
            "web_entrypoints": len(web_entrypoints),
            "visual_done": len(visual_done),
            "visual_failed": len(visual_failed),
            "report_sections": len(
                self.session.exec(select(AiAnalysis).where(AiAnalysis.scan_task_id == task_id, AiAnalysis.analysis_type.startswith("report_"))).all()
            ),
            "internet_assets": len(
                self.session.exec(select(InternetAsset).where(InternetAsset.id.in_(asset_ids))).all()
            )
            if asset_ids
            else 0,
            "company_rows": len(self.session.exec(select(Company).where(Company.id.in_(company_ids))).all())
            if company_ids
            else 0,
        }

    def _stages(self, task_id: int, counts: dict[str, int]) -> list[tuple[str, str, str]]:
        subdomain_task = self.session.exec(
            select(SubdomainEnumerationTask).where(SubdomainEnumerationTask.scan_task_id == task_id)
        ).first()
        nmap_task = self.session.exec(
            select(NmapScanTask).where(NmapScanTask.scan_task_id == task_id)
        ).first()
        classify_task = self.session.exec(
            select(AssetClassificationTask).where(AssetClassificationTask.scan_task_id == task_id)
        ).first()
        url_task = self.session.exec(
            select(UrlDiscoveryTask).where(UrlDiscoveryTask.scan_task_id == task_id)
        ).first()
        report_task = self.session.exec(
            select(ReportGenerationTask).where(ReportGenerationTask.scan_task_id == task_id)
        ).first()
        subdomain_failed_runs = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == task_id,
                SubdomainToolRun.status == "failed",
            )
        ).all()
        failed_dns_queries = self.session.exec(
            select(DnsQueryStatus).where(
                DnsQueryStatus.scan_task_id == task_id,
                DnsQueryStatus.status == "failed",
            )
        ).all()
        failed_nmap_runs = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == task_id,
                NmapScanRun.status == "failed",
            )
        ).all()
        subdomain_status = self._status_with_partial_failures(
            self._task_status(subdomain_task, counts["subdomains"] or counts["dns"]),
            len(subdomain_failed_runs) + len(failed_dns_queries),
        )
        nmap_status = self._status_with_partial_failures(
            self._task_status(nmap_task, counts["open_ports"]),
            len(failed_nmap_runs),
        )
        report_status, report_artifacts = self._report_status(report_task, counts["report_sections"])
        return [
            ("discover", self._done_if(counts["companies"] or counts["assets"]), f"companies={counts['companies']}, assets={counts['assets']}"),
            (
                "subdomains",
                subdomain_status,
                f"subdomains={counts['subdomains']}, dns_records={counts['dns']}, failed_items={len(subdomain_failed_runs) + len(failed_dns_queries)}",
            ),
            ("port-scan", nmap_status, f"open_ports={counts['open_ports']}, failed_runs={len(failed_nmap_runs)}"),
            ("classify", self._task_status(classify_task, counts["service_assets"]), f"services={counts['service_assets']}, web={counts['web_assets']}"),
            ("url-discover", self._task_status(url_task, counts["web_entrypoints"]), f"entrypoints={counts['web_entrypoints']}, visual_ok={counts['visual_done']}, visual_error={counts['visual_failed']}"),
            ("report", report_status, f"ai_sections={counts['report_sections']}, artifacts={report_artifacts}"),
        ]

    def _task_status(self, task, has_data: int) -> str:
        if task:
            if task.status == "running" and self._is_stale_running(task):
                return "running_stale_with_data" if has_data else "running_stale"
            if task.status in {"interrupted", "failed"} and has_data:
                return f"{task.status}_with_data"
            return task.status
        return self._done_if(has_data)

    def _status_with_partial_failures(self, status: str, failed_count: int) -> str:
        if status == "completed" and failed_count:
            return "completed_with_errors"
        return status

    def _report_status(self, task: ReportGenerationTask | None, section_count: int) -> tuple[str, str]:
        paths = [
            Path(value)
            for value in (
                getattr(task, "report_path", None),
                getattr(task, "asset_workbook_path", None),
                getattr(task, "web_workbook_path", None),
            )
            if value
        ]
        artifacts_ready = len(paths) == 3 and all(path.exists() and path.stat().st_size > 0 for path in paths)
        artifact_state = "ok" if artifacts_ready else "missing"
        if task:
            if task.status in {"failed", "interrupted"}:
                return task.status, artifact_state
            status = self._task_status(task, section_count)
            if status == "completed" and not artifacts_ready:
                return "completed_with_errors", artifact_state
            return status, artifact_state
        # Existing tasks from before report-generation tracking are complete
        # only when all AI chunks and the generated deliverables are present.
        if section_count >= 4 and artifacts_ready:
            return "completed", artifact_state
        return "pending", artifact_state

    def _is_stale_running(self, task) -> bool:
        started_at = getattr(task, "started_at", None)
        if not started_at:
            return False
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - started_at > STALE_RUNNING_AFTER

    def _done_if(self, value: int | bool) -> str:
        return "completed" if value else "pending"

    def _next_step(self, stages: list[tuple[str, str, str]]) -> str | None:
        commands = {
            "discover": "assetmap discover \"公司名称\"",
            "subdomains": "assetmap run <task_id> --from-stage subdomains",
            "port-scan": "assetmap run <task_id> --from-stage port-scan",
            "classify": "assetmap run <task_id> --from-stage classify",
            "url-discover": "assetmap run <task_id> --from-stage url-discover",
            "report": "assetmap run <task_id> --from-stage report",
        }
        rerun_commands = {
            "subdomains": "assetmap run <task_id> --from-stage subdomains --rerun-dns",
            "port-scan": "assetmap run <task_id> --from-stage port-scan --rerun-ports",
            "classify": "assetmap run <task_id> --from-stage classify --rerun-classify",
            "url-discover": "assetmap run <task_id> --from-stage url-discover --retry-failed",
            "report": "assetmap run <task_id> --from-stage report --rerun-ai",
        }
        for name, status, _ in stages:
            if status not in {"completed", "skipped"}:
                if status.endswith("_with_data") and name in rerun_commands:
                    return rerun_commands[name]
                return commands[name]
        return None
