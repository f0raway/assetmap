from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig
from assetmap.models import AiAnalysis, DnsRecord, NmapPort, NmapScanRun, NmapScanTask, OriginIpCandidate
from assetmap.services.mapping.fofa import FofaClient, FofaPort
from assetmap.services.runtime.tool_resolver import ToolResolver
from assetmap.services.runtime.work_units import WorkUnitTracker


NMAP_BATCH_TARGET = "__batch__"
NMAP_PREFLIGHT_TARGET = "__preflight__"
NMAP_TARGET_PREFIX = "__target__:"
NMAP_FOFA_VALIDATION_PREFIX = "__fofa_validation__:"
NMAP_SERVICE_DETECT_COMMAND = "{binary} -Pn -sV --version-intensity 5 -p {ports} {target} -oX {xml_output} -oN {normal_output}"
NMAP_PROGRESS_INTERVAL = "15s"
NMAP_SCRIPT_TIMEOUT = "60s"
NMAP_PREFLIGHT_PORTS = (1, 22, 80, 443, 3306, 8080, 49152, 65535)
NMAP_ACCEPT_ALL_MIN_OPEN_PORTS = 1024
NMAP_ACCEPT_ALL_TCPWRAPPED_RATIO = 0.98
PARKING_CNAME_KEYWORDS = ("expired.", "parking", "parked", "hichina.com")

IP_PATTERN = re.compile(
    r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9.])"
    r"|(?<![A-Za-z0-9:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![A-Za-z0-9:])"
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _quote(value: str) -> str:
    """Quote runtime values before interpolating them into a configured shell command."""
    if os.name == "nt":
        return subprocess.list2cmdline([value])
    return shlex.quote(value)


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
        self._log("[port] fixed sources: nmap, fofa")
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
            active_targets = self._preflight_targets(scan_task_id, targets, rerun=rerun)
            self._run_batch(scan_task_id, active_targets, rerun=rerun)
            self._run_fofa(scan_task_id, targets, rerun=rerun)
            self._validate_fofa_ports(scan_task_id, active_targets, rerun=rerun)
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
        """Run full-port scans as durable, serial, per-IP work units.

        ``__batch__`` is retained only as historical audit evidence.  It is no
        longer used for a new scan because an interrupted batch cannot tell us
        which targets were actually finished.
        """
        output_dir = self.config.data_path("nmap", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        if not targets:
            self._log("[nmap] full scan skipped: every target was flagged as TCP accept-all during preflight")
            return
        legacy = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == NMAP_BATCH_TARGET,
            )
        ).first()
        if legacy and legacy.status in {"interrupted", "failed", "running"}:
            self._log(
                "[nmap] detected an old interrupted batch record; it is retained for audit, "
                "and recovery now continues per IP instead of restarting that batch"
            )

        tracker = WorkUnitTracker(self.session, scan_task_id, "port-scan")
        self._log(f"[nmap] full-port scans serially: {len(targets)} independent IP jobs")
        for index, target in enumerate(targets, start=1):
            run = self._get_or_create_target_run(scan_task_id, target, output_dir, rerun=rerun)
            target_dir = output_dir / "targets"
            expected_command = self._scan_command(
                target_dir / f"{_safe_ip(target)}.txt",
                target_dir / f"{_safe_ip(target)}.xml",
                target_dir / f"{_safe_ip(target)}.nmap",
            )
            input_payload = {"policy": "nmap-full-port-per-ip-v1", "target": target, "command": expected_command}
            unit, changed = tracker.get_or_create(
                "nmap_full_port",
                target,
                input_payload,
            )
            if unit.status == "completed" and not rerun and WorkUnitTracker.completed_output_exists(unit) and not changed:
                self._log(f"[nmap] {index}/{len(targets)} skip completed: {target}")
                continue
            if unit.status == "completed" and not rerun and changed:
                self._log(
                    f"[nmap] {index}/{len(targets)} configuration changed after completed scan: {target}; "
                    "keep saved result (use --rerun-ports to scan again)"
                )
                continue
            if rerun:
                unit.input_fingerprint = tracker.fingerprint(input_payload)
                unit.status = "pending"
                self.session.add(unit)
                self.session.commit()
            if run.status == "completed" and not rerun and Path(run.xml_output_path).exists():
                tracker.complete(unit, output_path=run.xml_output_path, details={"nmap_run_id": run.id, "recovered": True})
                self._log(f"[nmap] {index}/{len(targets)} reuse completed scan record: {target}")
                continue
            if run.status == "running":
                run.status = "pending"
                run.error_message = "Recovered from previous interrupted run"
                self.session.add(run)
                self.session.commit()
            elif run.status in {"completed", "failed", "interrupted"}:
                run.status = "pending"
                self.session.add(run)
                self.session.commit()
            unit.input_fingerprint = tracker.fingerprint(input_payload)
            self.session.add(unit)
            self.session.commit()
            tracker.begin(unit)
            self._log(f"[nmap] {index}/{len(targets)} scanning: {target}")
            try:
                self._run_one(run.id)
            except KeyboardInterrupt:
                tracker.fail(unit, "Interrupted by user", interrupted=True)
                raise
            self.session.expire_all()
            saved_run = self.session.get(NmapScanRun, run.id) or run
            if saved_run.status == "completed" and Path(saved_run.xml_output_path).exists():
                tracker.complete(unit, output_path=saved_run.xml_output_path, details={"nmap_run_id": saved_run.id})
            else:
                tracker.fail(unit, saved_run.error_message or "Nmap did not produce a complete XML result")

    def _preflight_targets(self, scan_task_id: int, targets: list[str], rerun: bool = False) -> list[str]:
        """Exclude TCP accept-all responders before expensive full-port detection.

        An IP that accepts connections on several widely separated ports is not
        treated as a real all-port service host. It is preserved in the audit
        for review, while FOFA can still supply passive evidence for that IP.
        """
        output_dir = self.config.data_path("nmap", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        targets_file = output_dir / "preflight_targets.txt"
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        run = self._get_or_create_preflight_run(scan_task_id, targets_file, output_dir)
        tracker = WorkUnitTracker(self.session, scan_task_id, "port-scan")
        input_payload = {
            "policy": "nmap-accept-all-preflight-v1",
            "targets": targets,
            "sentinel_ports": list(NMAP_PREFLIGHT_PORTS),
            "command": run.command,
        }
        unit, changed = tracker.get_or_create("nmap_preflight", "all-targets", input_payload)
        if unit.status == "completed" and not rerun and not changed and Path(run.xml_output_path).exists():
            self._log("[nmap] preflight: reuse completed accept-all check")
        else:
            # A target-list change invalidates preflight output, but this is a
            # deliberately tiny eight-port safety check, not a full rescan.
            if run.status != "pending":
                run.status = "pending"
                self.session.add(run)
                self.session.commit()
            self._log(f"[nmap] preflight: checking {len(targets)} targets on {len(NMAP_PREFLIGHT_PORTS)} sentinel ports")
            unit.input_fingerprint = tracker.fingerprint(input_payload)
            self.session.add(unit)
            self.session.commit()
            tracker.begin(unit)
            try:
                self._run_one(run.id)
            except KeyboardInterrupt:
                tracker.fail(unit, "Interrupted by user", interrupted=True)
                raise
            self.session.expire_all()
            run = self.session.get(NmapScanRun, run.id) or run
            if run.status == "completed" and Path(run.xml_output_path).exists():
                tracker.complete(unit, output_path=run.xml_output_path, details={"nmap_run_id": run.id})
            else:
                tracker.fail(unit, run.error_message or "Nmap preflight did not produce a complete XML result")
        if run.status != "completed" or not Path(run.xml_output_path).exists():
            self._log("[nmap] preflight unavailable; keeping all targets for the full scan")
            return targets
        suspicious = self._preflight_accept_all_targets(Path(run.xml_output_path))
        self._write_port_anomaly_audit(
            scan_task_id,
            preflight={
                "checked_targets": targets,
                "sentinel_ports": list(NMAP_PREFLIGHT_PORTS),
                "accept_all_targets": suspicious,
                "active_scan_targets": [target for target in targets if target not in suspicious],
            },
        )
        if suspicious:
            self._log(
                f"[nmap] preflight excluded {len(suspicious)} TCP accept-all targets; "
                "they will not be represented as real open ports"
            )
            self._log(f"[nmap] preflight audit: {self._port_anomaly_audit_path(scan_task_id)}")
        return [target for target in targets if target not in suspicious]

    def _preflight_accept_all_targets(self, xml_path: Path) -> list[str]:
        root = ET.parse(xml_path).getroot()
        suspicious: list[str] = []
        expected = set(NMAP_PREFLIGHT_PORTS)
        for host in root.findall("host"):
            target_ip = self._host_ip(host)
            if not target_ip:
                continue
            open_ports = {
                int(port.attrib.get("portid", "0"))
                for port in host.findall("./ports/port")
                if port.attrib.get("protocol") == "tcp" and (port.find("state") is not None and port.find("state").attrib.get("state") == "open")
            }
            if expected.issubset(open_ports):
                suspicious.append(target_ip)
        return sorted(set(suspicious))

    def _validate_fofa_ports(self, scan_task_id: int, targets: list[str], rerun: bool = False) -> None:
        ports_by_ip = self._fofa_ports_by_ip(scan_task_id, targets)
        if not ports_by_ip:
            self._log("[nmap] fofa validation skipped: no passive ports")
            return
        jobs: list[int] = []
        for target, ports in ports_by_ip.items():
            run = self._get_or_create_fofa_validation_run(scan_task_id, target, ports)
            if run.status == "completed" and not rerun:
                self._log(f"[nmap] skip completed fofa validation: {target} ports={len(ports)}")
                continue
            if run.status == "running" and not rerun:
                self._log(f"[nmap] skip running fofa validation: {target}")
                continue
            if (rerun or run.status == "failed") and run.status in {"completed", "failed", "running"}:
                run.status = "pending"
                self.session.add(run)
                self.session.commit()
            if run.id:
                jobs.append(run.id)
        if not jobs:
            return
        total_ports = sum(len(ports) for ports in ports_by_ip.values())
        self._log(f"[nmap] validating FOFA passive ports serially: hosts={len(jobs)}, ports={total_ports}")
        for run_id in jobs:
            self._run_one(run_id)

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

    def _run_fofa(self, scan_task_id: int, targets: list[str], rerun: bool = False) -> None:
        client = FofaClient(self.config.fofa)
        if hasattr(client, "set_progress"):
            client.set_progress(self._log)
        tracker = WorkUnitTracker(self.session, scan_task_id, "port-scan")
        total = 0
        attempted = 0
        errors: list[dict[str, str]] = []
        self._log(f"[fofa] passive port lookup targets: {len(targets)}")
        for index, target in enumerate(targets, start=1):
            unit, changed = tracker.get_or_create(
                "fofa_ip_lookup",
                target,
                {"policy": "fofa-ip-port-lookup-v1", "target": target},
            )
            # Records created before work-unit tracking prove that FOFA was
            # queried successfully only when they contain at least one port.
            # A historical empty response cannot be inferred, so it is queried
            # once and then persisted as a completed zero-result unit.
            if unit.attempts == 0 and unit.status == "pending" and self._fofa_result_exists(scan_task_id, target):
                tracker.complete(unit, details={"migrated_from_port_evidence": True})
                unit = self.session.get(type(unit), unit.id) or unit
            if unit.status == "completed" and not rerun and not changed:
                ports_count = (unit.details or {}).get("ports_returned", 0)
                self._log(f"[fofa] {index}/{len(targets)} skip completed: {target}, ports={ports_count}")
                continue
            if unit.status == "completed" and not rerun and changed:
                self._log(
                    f"[fofa] {index}/{len(targets)} lookup policy changed: {target}; "
                    "keep saved result (use --rerun-ports to query again)"
                )
                continue
            if rerun:
                unit.input_fingerprint = tracker.fingerprint({"policy": "fofa-ip-port-lookup-v1", "target": target})
                unit.status = "pending"
                self.session.add(unit)
                self.session.commit()
            attempted += 1
            self._log(f"[fofa] {index}/{len(targets)} querying: {target}")
            unit.input_fingerprint = tracker.fingerprint({"policy": "fofa-ip-port-lookup-v1", "target": target})
            self.session.add(unit)
            self.session.commit()
            tracker.begin(unit)
            try:
                ports = client.search_ip_ports(target)
            except Exception as exc:
                message = self._safe_fofa_error(exc)
                tracker.fail(unit, message)
                errors.append({"target": target, "error": message})
                self._log(f"[fofa] {index}/{len(targets)} failed: {target} -> {message[:160]}")
                continue
            self._log(f"[fofa] {index}/{len(targets)} done: {target}, ports={len(ports)}")
            total += self._save_fofa_ports(scan_task_id, ports)
            tracker.complete(unit, details={"ports_returned": len(ports)})
        if errors:
            error_path = self._write_fofa_errors(scan_task_id, errors)
            self._log(f"[fofa] failures: {len(errors)}/{attempted}, details={error_path}")
        self._log(f"[fofa] passive ports merged: {total}")

    def _safe_fofa_error(self, exc: Exception) -> str:
        """Keep failures useful without ever persisting an API query URL or Key."""
        message = str(exc)
        message = message.replace(self.config.fofa.api_key, "[REDACTED_SECRET]")
        message = message.replace(self.config.fofa.email, "[REDACTED_EMAIL]")
        message = re.sub(r"https?://\S+", "[FOFA_REQUEST_URL_REDACTED]", message)
        return message[:500]

    def _write_fofa_errors(self, scan_task_id: int, errors: list[dict[str, str]]) -> Path:
        output_dir = self.config.data_path("nmap", f"task_{scan_task_id}")
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
        targets: list[str] = []
        for source in ("origin_confirmed", "manual_confirmed"):
            for value in by_source[source]:
                if value not in targets:
                    targets.append(value)
        self._log(
            "[port] target sources: "
            + ", ".join(f"{source}={len(by_source[source])}" for source in ("origin_confirmed", "manual_confirmed"))
            + f", merged={len(targets)}"
        )
        manifest = self._write_target_sources_manifest(scan_task_id, by_source, targets)
        self._log(f"[port] target source manifest: {manifest}")
        if not targets:
            raise ValueError(
                "No confirmed origin IPs found. Run domain mapping and review its candidates, "
                "or import a manual IP first."
            )
        return targets

    def _write_target_sources_manifest(self, scan_task_id: int, by_source: dict[str, list[str]], targets: list[str]) -> Path:
        output_dir = self.config.data_path("nmap", f"task_{scan_task_id}")
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
            "selection_policy": "only origin_ip_candidates decision=include or manual_confirmed",
            "source_counts": {source: len(values) for source, values in by_source.items()},
            "merged_count": len(targets),
            "merged_targets": targets,
            "sources_by_ip": {ip: sources_by_ip[ip] for ip in sorted(sources_by_ip)},
        }
        path = output_dir / "target_sources.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _targets_by_source(self, scan_task_id: int) -> dict[str, list[str]]:
        rows = self.session.exec(
            select(OriginIpCandidate).where(
                OriginIpCandidate.scan_task_id == scan_task_id,
                OriginIpCandidate.decision.in_(["include", "manual_confirmed"]),
            )
        ).all()
        output = {"origin_confirmed": [], "manual_confirmed": []}
        for row in rows:
            if not _is_real_public_ip(row.ip):
                continue
            source = "manual_confirmed" if row.decision == "manual_confirmed" else "origin_confirmed"
            output[source].append(row.ip)
        # A manual IP may be added after domain mapping. It is an explicit user
        # confirmation, so it can enter the remaining stages immediately.
        manual_rows = self.session.exec(
            select(DnsRecord).where(
                DnsRecord.scan_task_id == scan_task_id,
                DnsRecord.record_type.in_(["A", "AAAA"]),
            )
        ).all()
        for row in manual_rows:
            if (row.raw_payload or {}).get("kind") == "manual_ip" and _is_real_public_ip(row.value):
                output["manual_confirmed"].append(row.value)
        return {name: sorted(set(values)) for name, values in output.items()}

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
        executable = ToolResolver(self.config.tools, self.config.config_dir).nmap_executable()
        if not executable:
            raise ValueError(
                "nmap executable not found. Install Nmap manually and ensure it is in PATH, "
                "or install it under tools/nmap/."
            )
        return str(executable)

    def _scan_command(self, targets_file: Path, xml_output: Path, normal_output: Path) -> str:
        template = self.config.tools.nmap_command
        if "{" not in template and "%s" in template:
            values = [_quote(str(targets_file)), _quote(str(xml_output)), _quote(str(normal_output))]
            command = template % tuple(values[: template.count("%s")])
        else:
            command = template.format(
                binary=_quote(self._binary_path()),
                targets_file=_quote(str(targets_file)),
                target_file=_quote(str(targets_file)),
                xml_output=_quote(str(xml_output)),
                normal_output=_quote(str(normal_output)),
                output_dir=_quote(str(xml_output.parent)),
            )
        return self._ensure_service_version_detection(command)

    def _preflight_command(self, targets_file: Path, xml_output: Path, normal_output: Path) -> str:
        ports = ",".join(str(port) for port in NMAP_PREFLIGHT_PORTS)
        return (
            f"{_quote(self._binary_path())} -Pn -n --open --reason --max-retries 1 "
            f"-p {ports} -iL {_quote(str(targets_file))} "
            f"-oX {_quote(str(xml_output))} -oN {_quote(str(normal_output))} "
            f"--stats-every {NMAP_PROGRESS_INTERVAL}"
        )

    @staticmethod
    def _ensure_service_version_detection(command: str) -> str:
        """Guarantee service evidence and periodic Nmap progress output."""
        if re.search(r"(?:^|\s)-sV(?:\s|$)", command) or "--service-version" in command:
            with_service_detection = command
        else:
            with_service_detection = f"{command} -sV --version-intensity 5"
        if "--script-timeout" not in with_service_detection:
            with_service_detection = f"{with_service_detection} --script-timeout {NMAP_SCRIPT_TIMEOUT}"
        if "--stats-every" not in with_service_detection:
            with_service_detection = f"{with_service_detection} --stats-every {NMAP_PROGRESS_INTERVAL}"
        return with_service_detection

    def _service_detect_command(self, target: str, ports: list[int], xml_output: Path, normal_output: Path) -> str:
        template = NMAP_SERVICE_DETECT_COMMAND
        command = template.format(
            binary=_quote(self._binary_path()),
            target=_quote(target),
            ports=",".join(str(port) for port in sorted(set(ports))),
            xml_output=_quote(str(xml_output)),
            normal_output=_quote(str(normal_output)),
            output_dir=_quote(str(xml_output.parent)),
        )
        return self._ensure_service_version_detection(command)

    def _get_or_create_batch_run(self, scan_task_id: int, targets_file: Path, output_dir: Path) -> NmapScanRun:
        xml_output = output_dir / "nmap.xml"
        normal_output = output_dir / "nmap.txt"
        command = self._scan_command(targets_file, xml_output, normal_output)
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

    def _get_or_create_target_run(
        self,
        scan_task_id: int,
        target: str,
        output_dir: Path,
        *,
        rerun: bool = False,
    ) -> NmapScanRun:
        """Return the Nmap record for one IP without rewriting a saved run."""
        target_dir = output_dir / "targets"
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / f"{_safe_ip(target)}.txt"
        target_file.write_text(f"{target}\n", encoding="utf-8")
        xml_output = target_dir / f"{_safe_ip(target)}.xml"
        normal_output = target_dir / f"{_safe_ip(target)}.nmap"
        command = self._scan_command(target_file, xml_output, normal_output)
        target_key = f"{NMAP_TARGET_PREFIX}{target}"
        run = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == target_key,
            )
        ).first()
        if run:
            # A completed command is historical evidence.  Do not silently
            # replace it after a config edit; --rerun-ports is explicit intent.
            if rerun or run.status != "completed":
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

    def _get_or_create_preflight_run(self, scan_task_id: int, targets_file: Path, output_dir: Path) -> NmapScanRun:
        xml_output = output_dir / "preflight.xml"
        normal_output = output_dir / "preflight.txt"
        command = self._preflight_command(targets_file, xml_output, normal_output)
        run = self.session.exec(
            select(NmapScanRun).where(
                NmapScanRun.scan_task_id == scan_task_id,
                NmapScanRun.target_ip == NMAP_PREFLIGHT_TARGET,
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
            target_ip=NMAP_PREFLIGHT_TARGET,
            command=command,
            xml_output_path=str(xml_output),
            normal_output_path=str(normal_output),
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def _get_or_create_fofa_validation_run(self, scan_task_id: int, target: str, ports: list[int]) -> NmapScanRun:
        output_dir = self.config.data_path("nmap", f"task_{scan_task_id}", "fofa_validation")
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
            process: subprocess.Popen[str] | None = None
            try:
                process = subprocess.Popen(
                    run.command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                self._log(f"[nmap] {target_label}: running; progress is printed every {NMAP_PROGRESS_INTERVAL}")
                output_lines: list[str] = []
                if process.stdout:
                    for line in process.stdout:
                        output_lines.append(line)
                        text_line = line.strip()
                        if text_line:
                            self._log(f"[nmap] {target_label} | {text_line}")
                        run.stdout = "".join(output_lines)[-20000:]
                        session.add(run)
                        session.commit()
                return_code = process.wait()
                run.exit_code = return_code
                run.stdout = "".join(output_lines)[-20000:]
                run.stderr = ""
                run.status = "completed" if return_code == 0 else "failed"
                if return_code != 0:
                    run.error_message = run.stdout[-2000:]
                if Path(run.xml_output_path).exists():
                    try:
                        self._parse_xml(session, run)
                    except ET.ParseError as exc:
                        run.error_message = f"nmap XML parse failed: {exc}; text output retained"
            except KeyboardInterrupt:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                run.status = "interrupted"
                run.error_message = "Interrupted by user"
                run.finished_at = _utcnow()
                session.add(run)
                session.commit()
                raise
            except Exception as exc:
                run.status = "failed"
                run.error_message = str(exc)
            run.finished_at = _utcnow()
            session.add(run)
            session.commit()

    def _parse_xml(self, session: Session, run: NmapScanRun) -> None:
        root = ET.parse(run.xml_output_path).getroot()
        if run.target_ip == NMAP_PREFLIGHT_TARGET:
            # Preflight only decides whether a target can safely enter the full
            # scan. Its eight sentinel ports are not asset evidence.
            return
        validation_target = self._fofa_validation_target(run.target_ip)
        full_scan_target = self._full_scan_target(run.target_ip)
        if run.target_ip == NMAP_BATCH_TARGET:
            existing = session.exec(
                select(NmapPort).where(NmapPort.scan_task_id == run.scan_task_id)
            ).all()
        else:
            existing = session.exec(
                select(NmapPort).where(
                    NmapPort.scan_task_id == run.scan_task_id,
                    NmapPort.target_ip == (validation_target or full_scan_target or run.target_ip),
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
                target_ip = self._host_ip(host) or validation_target or full_scan_target or run.target_ip
                self._parse_host_ports(session, run.scan_task_id, target_ip, host.findall("./ports/port"))
            return
        self._parse_host_ports(
            session,
            run.scan_task_id,
            validation_target or full_scan_target or run.target_ip,
            root.findall(".//port"),
        )

    def _fofa_validation_target(self, value: str) -> str | None:
        return value[len(NMAP_FOFA_VALIDATION_PREFIX):] if value.startswith(NMAP_FOFA_VALIDATION_PREFIX) else None

    def _full_scan_target(self, value: str) -> str | None:
        return value[len(NMAP_TARGET_PREFIX):] if value.startswith(NMAP_TARGET_PREFIX) else None

    def _display_target(self, value: str) -> str:
        if value == NMAP_PREFLIGHT_TARGET:
            return "preflight"
        target = self._fofa_validation_target(value)
        if target:
            return f"{target} (FOFA ports)"
        return self._full_scan_target(value) or value

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
        if self._is_tcp_accept_all_response(ports):
            self._remove_active_port_evidence(session, scan_task_id, target_ip)
            self._write_port_anomaly_audit(
                scan_task_id,
                parser_fallback={
                    "target_ip": target_ip,
                    "open_tcp_ports": sum(
                        1
                        for port in ports
                        if port.attrib.get("protocol") == "tcp"
                        and port.find("state") is not None
                        and port.find("state").attrib.get("state") == "open"
                    ),
                    "tcpwrapped_ports": sum(
                        1
                        for port in ports
                        if port.attrib.get("protocol") == "tcp"
                        and port.find("state") is not None
                        and port.find("state").attrib.get("state") == "open"
                        and port.find("service") is not None
                        and port.find("service").attrib.get("name") == "tcpwrapped"
                    ),
                    "reason": "full_port_tcpwrapped_pattern",
                },
            )
            self._log(
                f"[nmap] abnormal TCP accept-all response: {target_ip}; "
                "discarded active all-port result and retained the audit evidence"
            )
            return
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

    @staticmethod
    def _is_tcp_accept_all_response(ports: list[ET.Element]) -> bool:
        open_tcp = [
            port
            for port in ports
            if port.attrib.get("protocol") == "tcp"
            and port.find("state") is not None
            and port.find("state").attrib.get("state") == "open"
        ]
        if len(open_tcp) < NMAP_ACCEPT_ALL_MIN_OPEN_PORTS:
            return False
        tcpwrapped = sum(
            1
            for port in open_tcp
            if port.find("service") is not None and port.find("service").attrib.get("name") == "tcpwrapped"
        )
        return tcpwrapped / len(open_tcp) >= NMAP_ACCEPT_ALL_TCPWRAPPED_RATIO

    def _remove_active_port_evidence(self, session: Session, scan_task_id: int, target_ip: str) -> None:
        rows = session.exec(
            select(NmapPort).where(
                NmapPort.scan_task_id == scan_task_id,
                NmapPort.target_ip == target_ip,
            )
        ).all()
        for row in rows:
            if not self._is_fofa_port(row):
                session.delete(row)
        session.commit()

    def _port_anomaly_audit_path(self, scan_task_id: int) -> Path:
        return self.config.data_path("nmap", f"task_{scan_task_id}", "port_anomaly_audit.json")

    def _write_port_anomaly_audit(
        self,
        scan_task_id: int,
        *,
        preflight: dict | None = None,
        parser_fallback: dict | None = None,
    ) -> Path:
        path = self._port_anomaly_audit_path(scan_task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict = {}
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
        payload.update(
            {
                "scan_task_id": scan_task_id,
                "generated_at": _utcnow().isoformat(),
                "policy": {
                    "preflight_sentinel_ports": list(NMAP_PREFLIGHT_PORTS),
                    "preflight_rule": "all sentinel ports open",
                    "parser_fallback_min_open_tcp_ports": NMAP_ACCEPT_ALL_MIN_OPEN_PORTS,
                    "parser_fallback_min_tcpwrapped_ratio": NMAP_ACCEPT_ALL_TCPWRAPPED_RATIO,
                    "handling": "do not store active all-port results as assets; retain passive FOFA evidence only",
                },
            }
        )
        if preflight is not None:
            payload["preflight"] = preflight
        if parser_fallback is not None:
            fallback = list(payload.get("parser_fallback") or [])
            if parser_fallback not in fallback:
                fallback.append(parser_fallback)
            payload["parser_fallback"] = fallback
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
