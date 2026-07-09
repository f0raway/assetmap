from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig
from assetmap.models import AiAnalysis, DnsRecord, NmapPort, NmapScanRun, NmapScanTask
from assetmap.services.fofa import FofaClient, FofaPort
from assetmap.services.tool_resolver import ToolResolver


NMAP_BATCH_TARGET = "__batch__"
NMAP_FOFA_VALIDATION_PREFIX = "__fofa_validation__:"
PARKING_CNAME_KEYWORDS = ("expired.", "parking", "parked", "hichina.com")

IP_PATTERN = re.compile(
    r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9.])"
    r"|(?<![A-Za-z0-9:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![A-Za-z0-9:])"
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _quote(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _safe_ip(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.replace(":", "_").replace(".", "_"))


def _is_real_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ipaddress.ip_address(value) in ipaddress.ip_network("198.18.0.0/15")


def extract_ai_marked_service_ips(analysis_text: str) -> list[str]:
    if not analysis_text:
        return []
    block_match = re.search(
        r"NMAP_TARGET_IPS\s*(.*?)\s*END_NMAP_TARGET_IPS",
        analysis_text,
        flags=re.I | re.S,
    )
    if block_match:
        return _extract_public_ips(block_match.group(1))
    segment = analysis_text
    start = analysis_text.find("真实公网")
    if start != -1:
        segment = analysis_text[start:]
    end_match = re.search(r"\n\s*(?:#{2,3}\s*二|---)", segment)
    if end_match:
        segment = segment[: end_match.start()]
    return _extract_public_ips(segment)


def _extract_public_ips(text: str) -> list[str]:
    ips = []
    for match in IP_PATTERN.finditer(text):
        value = match.group(0)
        if _is_real_public_ip(value) and value not in ips:
            ips.append(value)
    return ips


class NmapScanService:
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

    def run(self, scan_task_id: int, rerun: bool = False) -> int:
        targets = self._targets(scan_task_id)
        sources = self._sources()
        self._log(f"[port] sources enabled: {', '.join(sorted(sources))}")
        task = self._get_or_create_task(scan_task_id)
        task.status = "running"
        task.started_at = task.started_at or _utcnow()
        task.error_message = None
        task.targets = targets
        self.session.add(task)
        self.session.commit()
        try:
            self._reset_stale_running_runs(scan_task_id)
            self._log(f"[port] targets: {len(targets)}")
            if "nmap" not in sources:
                self._run_fofa(scan_task_id, targets, rerun=rerun, required=True)
                self._log_port_summary(scan_task_id)
                task.status = "completed"
                task.finished_at = _utcnow()
                self.session.add(task)
                self.session.commit()
                return task.id
            if self.config.tools.nmap_mode.lower() == "batch":
                self._run_batch(scan_task_id, targets, rerun=rerun)
                if "fofa" in sources:
                    self._run_fofa(scan_task_id, targets, rerun=rerun, required=False)
                self._validate_fofa_ports(scan_task_id, targets, rerun=rerun)
                self._log_port_summary(scan_task_id)
                task.status = "completed"
                task.finished_at = _utcnow()
                self.session.add(task)
                self.session.commit()
                return task.id
            jobs: list[int] = []
            for target in targets:
                run = self._get_or_create_run(scan_task_id, target)
                if run.status in {"completed", "failed"} and not rerun:
                    self._log(f"[nmap] skip {run.status}: {target}")
                    continue
                if run.status == "running" and not rerun:
                    self._log(f"[nmap] skip running: {target} (use --rerun to restart)")
                    continue
                if rerun and run.status in {"completed", "failed", "running"}:
                    run.status = "pending"
                    self.session.add(run)
                    self.session.commit()
                if run.id:
                    jobs.append(run.id)
            if jobs:
                workers = min(max(1, self.config.tools.nmap_max_workers), len(jobs))
                self._log(f"[nmap] running {len(jobs)} scans with {workers} workers")
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(self._run_one, run_id) for run_id in jobs]
                    for future in as_completed(futures):
                        future.result()
            if "fofa" in sources:
                self._run_fofa(scan_task_id, targets, rerun=rerun, required=False)
            self._validate_fofa_ports(scan_task_id, targets, rerun=rerun)
            self._log_port_summary(scan_task_id)
            task.status = "completed"
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            return task.id
        except KeyboardInterrupt:
            task.status = "interrupted"
            task.error_message = "Interrupted by user"
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            self._log(f"[nmap] task {task.id} interrupted by user")
            raise
        except Exception as exc:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            raise

    def _sources(self) -> set[str]:
        sources = {source.lower().strip() for source in self.config.port_scan.sources_enabled if source.strip()}
        unsupported = sources - {"nmap", "fofa"}
        if unsupported:
            raise ValueError(f"Unsupported port scan sources: {', '.join(sorted(unsupported))}")
        if not sources:
            raise ValueError("No port scan sources enabled. Use port_scan.sources_enabled.")
        return sources

    def _reset_stale_running_runs(self, scan_task_id: int) -> None:
        rows = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.status == "running",
            )
        ).all()
        for row in rows:
            row.status = "pending"
            row.error_message = "Recovered from previous interrupted run"
            self.session.add(row)
        if rows:
            self.session.commit()

    def _run_batch(self, scan_task_id: int, targets: list[str], rerun: bool = False) -> None:
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        targets_file = output_dir / "ip.txt"
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        run = self._get_or_create_batch_run(scan_task_id, targets_file, output_dir)
        if run.status in {"completed", "failed"} and not rerun:
            self._log(f"[nmap] skip {run.status} batch scan: {targets_file}")
            return
        if run.status == "running" and not rerun:
            self._log("[nmap] skip running batch scan (use --rerun to restart)")
            return
        if rerun and run.status in {"completed", "failed", "running"}:
            run.status = "pending"
            self.session.add(run)
            self.session.commit()
        if run.id:
            self._log(f"[nmap] batch scan with -iL {targets_file}")
            self._run_one(run.id)

    def _validate_fofa_ports(self, scan_task_id: int, targets: list[str], rerun: bool = False) -> None:
        ports_by_ip = self._fofa_ports_by_ip(scan_task_id, targets)
        if not ports_by_ip:
            self._log("[nmap] fofa validation skipped: no passive ports")
            return
        jobs: list[int] = []
        for target, ports in ports_by_ip.items():
            run = self._get_or_create_fofa_validation_run(scan_task_id, target, ports)
            if run.status in {"completed", "failed"} and not rerun:
                self._log(f"[nmap] skip {run.status} fofa validation: {target} ports={len(ports)}")
                continue
            if run.status == "running" and not rerun:
                self._log(f"[nmap] skip running fofa validation: {target}")
                continue
            if rerun and run.status in {"completed", "failed", "running"}:
                run.status = "pending"
                self.session.add(run)
                self.session.commit()
            if run.id:
                jobs.append(run.id)
        if not jobs:
            return
        workers = min(max(1, self.config.tools.nmap_max_workers), len(jobs))
        total_ports = sum(len(ports) for ports in ports_by_ip.values())
        self._log(f"[nmap] validating FOFA passive ports: hosts={len(jobs)}, ports={total_ports}, workers={workers}")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._run_one, run_id) for run_id in jobs]
            for future in as_completed(futures):
                future.result()

    def _fofa_ports_by_ip(self, scan_task_id: int, targets: list[str]) -> dict[str, list[int]]:
        target_set = set(targets)
        rows = self.session.exec(
            select(NmapPort).where(
                NmapPort.scan_task_id == scan_task_id,
                NmapPort.state == "open",
            )
        ).all()
        output: dict[str, list[int]] = {}
        for row in rows:
            if row.target_ip not in target_set or not self._is_fofa_port(row):
                continue
            if self._has_nmap_evidence(row):
                continue
            output.setdefault(row.target_ip, [])
            if row.port not in output[row.target_ip]:
                output[row.target_ip].append(row.port)
        return {ip: sorted(ports) for ip, ports in sorted(output.items()) if ports}

    def _run_fofa(self, scan_task_id: int, targets: list[str], rerun: bool = False, required: bool = False) -> None:
        client = FofaClient(self.config.fofa)
        total = 0
        attempted = 0
        errors: list[dict[str, str]] = []
        self._log(f"[fofa] passive port lookup targets: {len(targets)}")
        for target in targets:
            if not rerun and self._fofa_result_exists(scan_task_id, target):
                self._log(f"[fofa] skip existing: {target}")
                continue
            attempted += 1
            try:
                ports = client.search_ip_ports(target)
            except Exception as exc:
                message = str(exc)[:500]
                errors.append({"target": target, "error": message})
                self._log(f"[fofa] {target}: failed -> {message[:160]}")
                continue
            self._log(f"[fofa] {target}: {len(ports)} ports")
            total += self._save_fofa_ports(scan_task_id, ports)
        if errors:
            error_path = self._write_fofa_errors(scan_task_id, errors)
            self._log(f"[fofa] failures: {len(errors)}/{attempted}, details={error_path}")
            if required and attempted and len(errors) == attempted and total == 0:
                raise RuntimeError(f"FOFA passive lookup failed for all targets. See {error_path}")
        self._log(f"[fofa] passive ports merged: {total}")

    def _write_fofa_errors(self, scan_task_id: int, errors: list[dict[str, str]]) -> Path:
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "fofa_errors.json"
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "error_count": len(errors),
            "errors": errors,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _fofa_result_exists(self, scan_task_id: int, target_ip: str) -> bool:
        rows = self.session.exec(
            select(NmapPort).where(
                NmapPort.scan_task_id == scan_task_id,
                NmapPort.target_ip == target_ip,
            )
        ).all()
        return any(self._is_fofa_port(row) for row in rows)

    def _save_fofa_ports(self, scan_task_id: int, ports: list[FofaPort]) -> int:
        count = 0
        for item in ports:
            record = self.session.exec(
                select(NmapPort).where(
                    NmapPort.scan_task_id == scan_task_id,
                    NmapPort.target_ip == item.ip,
                    NmapPort.protocol == "tcp",
                    NmapPort.port == item.port,
                )
            ).first()
            payload = {
                "source": "fofa",
                "host": item.host,
                "title": item.title,
                "server": item.server,
                "raw": item.raw or {},
            }
            if record:
                sources = (record.raw_payload or {}).get("sources") or [(record.raw_payload or {}).get("source", "nmap")]
                if "fofa" not in sources:
                    sources.append("fofa")
                record.raw_payload = {**(record.raw_payload or {}), "sources": sources, "fofa": payload}
                record.service = record.service or item.protocol or None
                record.product = record.product or item.server or None
                self.session.add(record)
                self.session.commit()
                continue
            record = NmapPort(
                scan_task_id=scan_task_id,
                target_ip=item.ip,
                protocol="tcp",
                port=item.port,
                state="open",
                service=item.protocol or None,
                product=item.server or None,
                raw_payload=payload,
            )
            self.session.add(record)
            try:
                self.session.commit()
                count += 1
            except IntegrityError:
                self.session.rollback()
        return count

    def _is_fofa_port(self, record: NmapPort) -> bool:
        payload = record.raw_payload or {}
        return payload.get("source") == "fofa" or "fofa" in (payload.get("sources") or [])

    def _has_nmap_evidence(self, record: NmapPort) -> bool:
        payload = record.raw_payload or {}
        sources = payload.get("sources")
        if isinstance(sources, list):
            return "nmap" in sources
        return payload.get("source") not in {"fofa"} and not isinstance(payload.get("fofa"), dict)

    def _log_port_summary(self, scan_task_id: int) -> None:
        rows = self.session.exec(
            select(NmapPort).where(
                NmapPort.scan_task_id == scan_task_id,
                NmapPort.state == "open",
            )
        ).all()
        passive_only = sum(1 for row in rows if self._is_fofa_port(row) and not self._has_nmap_evidence(row))
        active_only = sum(1 for row in rows if self._has_nmap_evidence(row) and not self._is_fofa_port(row))
        active_and_passive = sum(1 for row in rows if self._has_nmap_evidence(row) and self._is_fofa_port(row))
        merged = len(rows)
        top_ports: dict[int, int] = {}
        for row in rows:
            top_ports[row.port] = top_ports.get(row.port, 0) + 1
        top = ", ".join(f"{port}({count})" for port, count in sorted(top_ports.items(), key=lambda item: (-item[1], item[0]))[:10])
        self._log(
            f"[port] open ports merged: total={merged}, "
            f"nmap_only={active_only}, fofa_only={passive_only}, active_and_passive={active_and_passive}"
        )
        if top:
            self._log(f"[port] top open ports: {top}")

    def _targets(self, scan_task_id: int) -> list[str]:
        by_source = self._targets_by_source(scan_task_id)
        enabled_sources = self._target_sources()
        targets: list[str] = []
        for source in enabled_sources:
            for value in by_source[source]:
                if value not in targets:
                    targets.append(value)
        self._log(
            "[port] target sources: "
            + ", ".join(f"{source}={len(by_source[source])}" for source in enabled_sources)
            + f", merged={len(targets)}"
        )
        manifest = self._write_target_sources_manifest(scan_task_id, by_source, targets)
        self._log(f"[port] target source manifest: {manifest}")
        if not targets:
            raise ValueError(
                "No port scan target IPs found. Run subdomains, enable DNS/AI target sources, "
                "or import manual IPs first."
            )
        return targets

    def _write_target_sources_manifest(self, scan_task_id: int, by_source: dict[str, list[str]], targets: list[str]) -> Path:
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        sources_by_ip: dict[str, list[str]] = {}
        for source, values in by_source.items():
            for value in values:
                sources_by_ip.setdefault(value, [])
                if source not in sources_by_ip[value]:
                    sources_by_ip[value].append(source)
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "target_sources_enabled": self._target_sources(),
            "source_counts": {source: len(values) for source, values in by_source.items()},
            "merged_count": len(targets),
            "merged_targets": targets,
            "sources_by_ip": {ip: sources_by_ip[ip] for ip in sorted(sources_by_ip)},
        }
        path = output_dir / "target_sources.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _targets_by_source(self, scan_task_id: int) -> dict[str, list[str]]:
        all_sources = {
            "ai": self._targets_from_ai(scan_task_id),
            "manual": self._targets_from_manual_ips(scan_task_id),
            "dns_public": self._targets_from_dns_public(scan_task_id),
        }
        return {source: all_sources[source] for source in self._target_sources()}

    def _target_sources(self) -> list[str]:
        sources = [source.lower().strip() for source in self.config.port_scan.target_sources_enabled if source.strip()]
        unsupported = set(sources) - {"ai", "manual", "dns_public"}
        if unsupported:
            raise ValueError(f"Unsupported port scan target sources: {', '.join(sorted(unsupported))}")
        if not sources:
            raise ValueError("No port scan target sources enabled. Use port_scan.target_sources_enabled.")
        return sources

    def _targets_from_ai(self, scan_task_id: int) -> list[str]:
        rows = self.session.exec(
            select(AiAnalysis).where(
                AiAnalysis.scan_task_id == scan_task_id,
                AiAnalysis.status == "completed",
                AiAnalysis.analysis_type == "dns_inference",
            )
        ).all()
        targets: list[str] = []
        for row in rows:
            for value in extract_ai_marked_service_ips(row.summary or ""):
                if value not in targets:
                    targets.append(value)
        return targets

    def _targets_from_manual_ips(self, scan_task_id: int) -> list[str]:
        rows = self.session.exec(
            select(DnsRecord).where(
                DnsRecord.scan_task_id == scan_task_id,
                DnsRecord.record_type.in_(["A", "AAAA"]),
            )
        ).all()
        targets: list[str] = []
        for row in rows:
            if (row.raw_payload or {}).get("kind") != "manual_ip":
                continue
            if _is_real_public_ip(row.value) and row.value not in targets:
                targets.append(row.value)
        return targets

    def _targets_from_dns_public(self, scan_task_id: int) -> list[str]:
        rows = self.session.exec(
            select(DnsRecord).where(
                DnsRecord.scan_task_id == scan_task_id,
            )
        ).all()
        parked_hosts = {
            row.fqdn
            for row in rows
            if row.record_type == "CNAME" and self._is_parking_cname(row.value)
        }
        external_cname_hosts = {
            row.fqdn
            for row in rows
            if row.record_type == "CNAME" and not self._is_same_root_cname(row.value, row.root_domain)
        }
        targets: list[str] = []
        for row in rows:
            if row.record_type not in {"A", "AAAA"}:
                continue
            if (row.raw_payload or {}).get("kind") == "manual_ip":
                continue
            if row.fqdn in parked_hosts or row.fqdn in external_cname_hosts:
                continue
            if _is_real_public_ip(row.value) and row.value not in targets:
                targets.append(row.value)
        return targets

    def _is_parking_cname(self, value: str) -> bool:
        text = value.lower().rstrip(".")
        return any(keyword in text for keyword in PARKING_CNAME_KEYWORDS)

    def _is_same_root_cname(self, value: str, root_domain: str) -> bool:
        cname = value.lower().rstrip(".")
        root = root_domain.lower().rstrip(".")
        return cname == root or cname.endswith(f".{root}")

    def _get_or_create_task(self, scan_task_id: int) -> NmapScanTask:
        task = self.session.exec(
            select(NmapScanTask).where(NmapScanTask.scan_task_id == scan_task_id)
        ).first()
        if task:
            return task
        task = NmapScanTask(scan_task_id=scan_task_id)
        self.session.add(task)
        self.session.commit()
        self.session.refresh(task)
        return task

    def _binary_path(self) -> str:
        executable = ToolResolver(self.config.tools).nmap_executable()
        if not executable:
            raise ValueError(
                "nmap executable not found. Install Nmap manually and ensure it is in PATH, "
                "or install it under tools/nmap/."
            )
        return str(executable)

    def _command(self, target: str, xml_output: Path, normal_output: Path) -> str:
        template = self.config.tools.nmap_command
        if "{" not in template and "%s" in template:
            values = [_quote(target), _quote(str(xml_output)), _quote(str(normal_output))]
            return template % tuple(values[: template.count("%s")])
        return template.format(
            binary=_quote(self._binary_path()),
            target=_quote(target),
            xml_output=_quote(str(xml_output)),
            normal_output=_quote(str(normal_output)),
            output_dir=_quote(str(xml_output.parent)),
        )

    def _batch_command(self, targets_file: Path, xml_output: Path, normal_output: Path) -> str:
        template = self.config.tools.nmap_batch_command
        if "{" not in template and "%s" in template:
            values = [_quote(str(targets_file)), _quote(str(xml_output)), _quote(str(normal_output))]
            return template % tuple(values[: template.count("%s")])
        return template.format(
            binary=_quote(self._binary_path()),
            targets_file=_quote(str(targets_file)),
            target_file=_quote(str(targets_file)),
            xml_output=_quote(str(xml_output)),
            normal_output=_quote(str(normal_output)),
            output_dir=_quote(str(xml_output.parent)),
        )

    def _service_detect_command(self, target: str, ports: list[int], xml_output: Path, normal_output: Path) -> str:
        template = self.config.tools.nmap_service_detect_command
        return template.format(
            binary=_quote(self._binary_path()),
            target=_quote(target),
            ports=",".join(str(port) for port in sorted(set(ports))),
            xml_output=_quote(str(xml_output)),
            normal_output=_quote(str(normal_output)),
            output_dir=_quote(str(xml_output.parent)),
        )

    def _get_or_create_batch_run(self, scan_task_id: int, targets_file: Path, output_dir: Path) -> NmapScanRun:
        xml_output = output_dir / "nmap.xml"
        normal_output = output_dir / "nmap.txt"
        command = self._batch_command(targets_file, xml_output, normal_output)
        run = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == NMAP_BATCH_TARGET,
            )
        ).first()
        if run:
            if run.command != command:
                run.status = "pending"
            run.command = command
            run.xml_output_path = str(xml_output)
            run.normal_output_path = str(normal_output)
            self.session.add(run)
            self.session.commit()
            return run
        run = NmapScanRun(
            scan_task_id=scan_task_id,
            target_ip=NMAP_BATCH_TARGET,
            command=command,
            xml_output_path=str(xml_output),
            normal_output_path=str(normal_output),
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def _get_or_create_run(self, scan_task_id: int, target: str) -> NmapScanRun:
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        xml_output = output_dir / f"{_safe_ip(target)}.xml"
        normal_output = output_dir / f"{_safe_ip(target)}.txt"
        command = self._command(target, xml_output, normal_output)
        run = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == target,
            )
        ).first()
        if run:
            if run.command != command:
                run.status = "pending"
            run.command = command
            run.xml_output_path = str(xml_output)
            run.normal_output_path = str(normal_output)
            self.session.add(run)
            self.session.commit()
            return run
        run = NmapScanRun(
            scan_task_id=scan_task_id,
            target_ip=target,
            command=command,
            xml_output_path=str(xml_output),
            normal_output_path=str(normal_output),
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def _get_or_create_fofa_validation_run(self, scan_task_id: int, target: str, ports: list[int]) -> NmapScanRun:
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}" / "fofa_validation"
        output_dir.mkdir(parents=True, exist_ok=True)
        port_key = "_".join(str(port) for port in sorted(set(ports)))[:120]
        xml_output = output_dir / f"{_safe_ip(target)}_{port_key}.xml"
        normal_output = output_dir / f"{_safe_ip(target)}_{port_key}.txt"
        command = self._service_detect_command(target, ports, xml_output, normal_output)
        target_key = f"{NMAP_FOFA_VALIDATION_PREFIX}{target}"
        run = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == target_key,
            )
        ).first()
        if run:
            if run.command != command:
                run.status = "pending"
            run.command = command
            run.xml_output_path = str(xml_output)
            run.normal_output_path = str(normal_output)
            self.session.add(run)
            self.session.commit()
            return run
        run = NmapScanRun(
            scan_task_id=scan_task_id,
            target_ip=target_key,
            command=command,
            xml_output_path=str(xml_output),
            normal_output_path=str(normal_output),
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def _run_one(self, run_id: int) -> None:
        with Session(self.session.get_bind()) as session:
            run = session.get(NmapScanRun, run_id)
            if not run:
                return
            run.status = "running"
            run.started_at = _utcnow()
            run.error_message = None
            session.add(run)
            session.commit()
            target_label = self._display_target(run.target_ip)
            self._log(f"[nmap] scan {target_label}")
            try:
                proc = subprocess.run(
                    run.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.config.tools.nmap_timeout_seconds,
                )
                run.exit_code = proc.returncode
                run.stdout = proc.stdout[-20000:]
                run.stderr = proc.stderr[-20000:]
                run.status = "completed" if proc.returncode == 0 else "failed"
                if proc.returncode != 0:
                    run.error_message = proc.stderr[-2000:] or proc.stdout[-2000:]
                if Path(run.xml_output_path).exists():
                    try:
                        self._parse_xml(session, run)
                    except ET.ParseError as exc:
                        run.error_message = f"nmap XML parse failed: {exc}; text output retained"
            except subprocess.TimeoutExpired as exc:
                run.status = "failed"
                run.exit_code = -1
                run.stdout = (exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else ""
                run.stderr = (exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else ""
                run.error_message = f"nmap timed out after {self.config.tools.nmap_timeout_seconds}s"
            except Exception as exc:
                run.status = "failed"
                run.error_message = str(exc)
            run.finished_at = _utcnow()
            session.add(run)
            session.commit()

    def _parse_xml(self, session: Session, run: NmapScanRun) -> None:
        root = ET.parse(run.xml_output_path).getroot()
        validation_target = self._fofa_validation_target(run.target_ip)
        if run.target_ip == NMAP_BATCH_TARGET:
            existing = session.exec(
                select(NmapPort).where(NmapPort.scan_task_id == run.scan_task_id)
            ).all()
        else:
            existing = session.exec(
                select(NmapPort).where(
                    NmapPort.scan_task_id == run.scan_task_id,
                    NmapPort.target_ip == (validation_target or run.target_ip),
                )
            ).all()
        if not validation_target:
            for record in existing:
                if not self._is_fofa_port(record):
                    session.delete(record)
            session.commit()
        hosts = root.findall("host")
        if hosts:
            for host in hosts:
                target_ip = self._host_ip(host) or validation_target or run.target_ip
                self._parse_host_ports(session, run.scan_task_id, target_ip, host.findall("./ports/port"))
            return
        self._parse_host_ports(session, run.scan_task_id, validation_target or run.target_ip, root.findall(".//port"))

    def _fofa_validation_target(self, value: str) -> str | None:
        return value[len(NMAP_FOFA_VALIDATION_PREFIX):] if value.startswith(NMAP_FOFA_VALIDATION_PREFIX) else None

    def _display_target(self, value: str) -> str:
        target = self._fofa_validation_target(value)
        return f"{target} (FOFA ports)" if target else value

    def _host_ip(self, host: ET.Element) -> str | None:
        for address in host.findall("address"):
            if address.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                return address.attrib.get("addr")
        address = host.find("address")
        return address.attrib.get("addr") if address is not None else None

    def _parse_host_ports(
        self,
        session: Session,
        scan_task_id: int,
        target_ip: str,
        ports: list[ET.Element],
    ) -> None:
        for port in ports:
            state_el = port.find("state")
            service_el = port.find("service")
            protocol = port.attrib.get("protocol", "")
            port_id = int(port.attrib.get("portid", "0"))
            raw_payload = {
                "source": "nmap",
                "port": port.attrib,
                "state": state_el.attrib if state_el is not None else {},
                "service": service_el.attrib if service_el is not None else {},
            }
            record = session.exec(
                select(NmapPort).where(
                    NmapPort.scan_task_id == scan_task_id,
                    NmapPort.target_ip == target_ip,
                    NmapPort.protocol == protocol,
                    NmapPort.port == port_id,
                )
            ).first()
            if record:
                sources = list((record.raw_payload or {}).get("sources") or [])
                existing_source = (record.raw_payload or {}).get("source")
                if existing_source and existing_source not in sources:
                    sources.append(existing_source)
                if self._is_fofa_port(record) and "fofa" not in sources:
                    sources.append("fofa")
                if "nmap" not in sources:
                    sources.append("nmap")
                record.raw_payload = {**(record.raw_payload or {}), "sources": sources, "nmap": raw_payload}
                record.state = state_el.attrib.get("state", "") if state_el is not None else record.state
                record.reason = state_el.attrib.get("reason") if state_el is not None else record.reason
                record.service = service_el.attrib.get("name") if service_el is not None else record.service
                record.product = service_el.attrib.get("product") if service_el is not None else record.product
                record.version = service_el.attrib.get("version") if service_el is not None else record.version
                record.extra_info = service_el.attrib.get("extrainfo") if service_el is not None else record.extra_info
            else:
                record = NmapPort(
                    scan_task_id=scan_task_id,
                    target_ip=target_ip,
                    protocol=protocol,
                    port=port_id,
                    state=state_el.attrib.get("state", "") if state_el is not None else "",
                    reason=state_el.attrib.get("reason") if state_el is not None else None,
                    service=service_el.attrib.get("name") if service_el is not None else None,
                    product=service_el.attrib.get("product") if service_el is not None else None,
                    version=service_el.attrib.get("version") if service_el is not None else None,
                    extra_info=service_el.attrib.get("extrainfo") if service_el is not None else None,
                    raw_payload=raw_payload,
                )
            session.add(record)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
