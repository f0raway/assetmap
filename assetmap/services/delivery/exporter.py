from __future__ import annotations

import csv
import json
from pathlib import Path

from sqlmodel import Session, select

from assetmap.models import (
    AiAnalysis,
    AssetClassificationTask,
    Company,
    CompanyAssetLink,
    CompanyEdge,
    DnsRecord,
    InternetAsset,
    NmapPort,
    NmapScanRun,
    NmapScanTask,
    OriginIpCandidate,
    ScanTask,
    ServiceAsset,
    SourceRawRecord,
    SubdomainEnumerationTask,
    SubdomainRecord,
    SubdomainToolRun,
    UrlDiscoveryTask,
    WebEntrypoint,
    WebProbeResult,
)


class ExportService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def export(self, task_id: int, fmt: str, output_dir: Path | str = "exports") -> Path:
        output_root = Path(output_dir)
        output_root.mkdir(parents=True, exist_ok=True)
        bundle = self._bundle(task_id)
        if fmt == "json":
            path = output_root / f"task_{task_id}.json"
            path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
            return path
        if fmt == "md":
            path = output_root / f"task_{task_id}.md"
            path.write_text(self._to_markdown(bundle), encoding="utf-8")
            return path
        if fmt == "csv":
            directory = output_root / f"task_{task_id}_csv"
            directory.mkdir(parents=True, exist_ok=True)
            self._write_csv(directory / "companies.csv", bundle["companies"])
            self._write_csv(directory / "edges.csv", bundle["edges"])
            self._write_csv(directory / "assets.csv", bundle["assets"])
            self._write_csv(directory / "raw_records.csv", bundle["raw_records"])
            self._write_csv(directory / "origin_ip_candidates.csv", bundle["origin_ip_candidates"])
            self._write_csv(directory / "nmap_runs.csv", bundle["nmap_runs"])
            self._write_csv(directory / "nmap_ports.csv", bundle["nmap_ports"])
            self._write_csv(directory / "service_assets.csv", bundle["service_assets"])
            self._write_csv(directory / "web_probe_results.csv", bundle["web_probe_results"])
            self._write_csv(directory / "web_entrypoints.csv", bundle["web_entrypoints"])
            return directory
        raise ValueError(f"Unsupported format: {fmt}")

    def _bundle(self, task_id: int) -> dict:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        edges = self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        company_ids = {edge.parent_company_id for edge in edges} | {edge.child_company_id for edge in edges}
        links = self.session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        company_ids.update(link.company_id for link in links)
        companies = (
            self.session.exec(select(Company).where(Company.id.in_(company_ids))).all()
            if company_ids
            else []
        )
        assets = {
            asset.id: asset
            for asset in self.session.exec(
                select(InternetAsset).where(
                    InternetAsset.id.in_(select(CompanyAssetLink.asset_id).where(CompanyAssetLink.task_id == task_id))
                )
            ).all()
        }
        raw_records = self.session.exec(select(SourceRawRecord).where(SourceRawRecord.task_id == task_id)).all()
        subtask = self.session.exec(
            select(SubdomainEnumerationTask).where(SubdomainEnumerationTask.scan_task_id == task_id)
        ).first()
        subdomains = self.session.exec(
            select(SubdomainRecord).where(SubdomainRecord.scan_task_id == task_id)
        ).all()
        dns_records = self.session.exec(
            select(DnsRecord).where(DnsRecord.scan_task_id == task_id)
        ).all()
        origin_ip_candidates = self.session.exec(
            select(OriginIpCandidate).where(OriginIpCandidate.scan_task_id == task_id)
        ).all()
        tool_runs = self.session.exec(
            select(SubdomainToolRun).where(SubdomainToolRun.scan_task_id == task_id)
        ).all()
        ai_analyses = self.session.exec(
            select(AiAnalysis).where(AiAnalysis.scan_task_id == task_id)
        ).all()
        nmap_task = self.session.exec(
            select(NmapScanTask).where(NmapScanTask.scan_task_id == task_id)
        ).first()
        nmap_runs = self.session.exec(
            select(NmapScanRun).where(NmapScanRun.scan_task_id == task_id)
        ).all()
        nmap_ports = self.session.exec(
            select(NmapPort).where(NmapPort.scan_task_id == task_id)
        ).all()
        classification_task = self.session.exec(
            select(AssetClassificationTask).where(AssetClassificationTask.scan_task_id == task_id)
        ).first()
        service_assets = self.session.exec(
            select(ServiceAsset).where(ServiceAsset.scan_task_id == task_id)
        ).all()
        web_probe_results = self.session.exec(
            select(WebProbeResult).where(WebProbeResult.scan_task_id == task_id)
        ).all()
        url_discovery_task = self.session.exec(
            select(UrlDiscoveryTask).where(UrlDiscoveryTask.scan_task_id == task_id)
        ).first()
        web_entrypoints = self.session.exec(
            select(WebEntrypoint).where(WebEntrypoint.scan_task_id == task_id)
        ).all()
        asset_rows = []
        for link in links:
            asset = assets.get(link.asset_id)
            if not asset:
                continue
            existing = next(
                (
                    row
                    for row in asset_rows
                    if row["company_id"] == link.company_id and row["id"] == asset.id
                ),
                None,
            )
            if existing:
                if link.source_tool not in existing["source_tools"]:
                    existing["source_tools"].append(link.source_tool)
                existing["source_tool"] = ",".join(existing["source_tools"])
                existing.setdefault("source_payloads", []).append(link.raw_payload)
                continue
            asset_rows.append(
                {
                    **asset.model_dump(mode="json"),
                    "company_id": link.company_id,
                    "source_tool": link.source_tool,
                    "source_tools": [link.source_tool],
                    "source_payloads": [link.raw_payload],
                    "observed_at": link.observed_at.isoformat(),
                }
            )
        return {
            "task": task.model_dump(mode="json"),
            "companies": [company.model_dump(mode="json") for company in companies],
            "edges": [edge.model_dump(mode="json") for edge in edges],
            "assets": asset_rows,
            "raw_records": [
                {
                    "source": record.source,
                    "action": record.action,
                    "parameter_hash": record.parameter_hash,
                    "request_payload": record.request_payload,
                    "response_json": record.response_json,
                    "created_at": record.created_at.isoformat(),
                }
                for record in raw_records
            ],
            "subdomain_task": subtask.model_dump(mode="json") if subtask else None,
            "subdomains": [row.model_dump(mode="json") for row in subdomains],
            "dns_records": [row.model_dump(mode="json") for row in dns_records],
            "origin_ip_candidates": [row.model_dump(mode="json") for row in origin_ip_candidates],
            "subdomain_tool_runs": [
                {
                    "root_domain": row.root_domain,
                    "tool_name": row.tool_name,
                    "status": row.status,
                    "exit_code": row.exit_code,
                    "output_path": row.output_path,
                    "error_message": row.error_message,
                }
                for row in tool_runs
            ],
            "ai_analyses": [row.model_dump(mode="json") for row in ai_analyses],
            "nmap_task": nmap_task.model_dump(mode="json") if nmap_task else None,
            "nmap_runs": [
                {
                    "target_ip": row.target_ip,
                    "status": row.status,
                    "exit_code": row.exit_code,
                    "command": row.command,
                    "xml_output_path": row.xml_output_path,
                    "normal_output_path": row.normal_output_path,
                    "error_message": row.error_message,
                }
                for row in nmap_runs
            ],
            "nmap_ports": [row.model_dump(mode="json") for row in nmap_ports],
            "classification_task": classification_task.model_dump(mode="json") if classification_task else None,
            "service_assets": [row.model_dump(mode="json") for row in service_assets],
            "web_probe_results": [row.model_dump(mode="json") for row in web_probe_results],
            "url_discovery_task": url_discovery_task.model_dump(mode="json") if url_discovery_task else None,
            "web_entrypoints": [row.model_dump(mode="json") for row in web_entrypoints],
        }

    def _write_csv(self, path: Path, rows: list[dict]) -> None:
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _to_markdown(self, bundle: dict) -> str:
        lines = [
            f"# Task {bundle['task']['id']}",
            "",
            f"- Target: {bundle['task']['target']}",
            f"- Status: {bundle['task']['status']}",
            f"- Companies: {len(bundle['companies'])}",
            f"- Assets: {len(bundle['assets'])}",
            f"- Nmap targets: {len(bundle['nmap_runs'])}",
            f"- Open ports: {len([port for port in bundle['nmap_ports'] if port.get('state') == 'open'])}",
            f"- Web assets: {len([asset for asset in bundle['service_assets'] if asset.get('asset_kind') == 'web'])}",
            f"- Non-web assets: {len([asset for asset in bundle['service_assets'] if asset.get('asset_kind') == 'non_web'])}",
            f"- Web entrypoints: {len(bundle['web_entrypoints'])}",
            "",
            "## Company Edges",
            "",
            "| Parent | Child | Direct | Cumulative | Depth |",
            "| --- | --- | --- | --- | --- |",
        ]
        company_map = {item["id"]: item["name"] for item in bundle["companies"]}
        for edge in bundle["edges"]:
            lines.append(
                f"| {company_map.get(edge['parent_company_id'], edge['parent_company_id'])} "
                f"| {company_map.get(edge['child_company_id'], edge['child_company_id'])} "
                f"| {edge['direct_holding_ratio']:.2%} | {edge['cumulative_holding_ratio']:.2%} | {edge['depth']} |"
            )
        lines.extend(
            [
                "",
                "## Assets",
                "",
                "| Company | Type | Identifier | Source Tool |",
                "| --- | --- | --- | --- |",
            ]
        )
        for asset in bundle["assets"]:
            lines.append(
                f"| {company_map.get(asset['company_id'], asset['company_id'])} "
                f"| {asset['asset_type']} | {asset['normalized_identifier']} | {asset['source_tool']} |"
            )
        if bundle["nmap_ports"]:
            lines.extend(
                [
                    "",
                    "## Nmap Ports",
                    "",
                    "| Target | Protocol | Port | State | Service | Product | Version |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for port in bundle["nmap_ports"]:
                lines.append(
                    f"| {port['target_ip']} | {port['protocol']} | {port['port']} | {port['state']} "
                    f"| {port.get('service') or ''} | {port.get('product') or ''} | {port.get('version') or ''} |"
                )
        if bundle["service_assets"]:
            lines.extend(
                [
                    "",
                    "## Service Assets",
                    "",
                    "| Kind | Target | Host Mode | Service | App | Title |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            for asset in bundle["service_assets"]:
                target = f"{asset['target_ip']}:{asset['port']}"
                service = " ".join(
                    item for item in (asset.get("service"), asset.get("product"), asset.get("version")) if item
                )
                lines.append(
                    f"| {asset['asset_kind']} | {target} | {asset.get('host_mode') or ''} "
                    f"| {service} | {asset.get('app_name') or ''} | {asset.get('title') or ''} |"
                )
        if bundle["web_entrypoints"]:
            lines.extend(
                [
                    "",
                    "## Web Entrypoints",
                    "",
                    "| URL | Status | Title | System | Purpose | Tech | Rendered HTML |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for entry in bundle["web_entrypoints"]:
                visual = (entry.get("evidence") or {}).get("visual_analysis") or {}
                lines.append(
                    f"| {entry['url']} | {entry.get('http_status') or ''} "
                    f"| {entry.get('title') or ''} | {visual.get('system_name') or ''} "
                    f"| {visual.get('site_purpose') or ''} | {', '.join(entry.get('tech_stack') or [])} "
                    f"| {visual.get('rendered_html_path') or ''} |"
                )
        return "\n".join(lines) + "\n"
