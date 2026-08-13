from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig, HTTPX_RATE_LIMIT, HTTPX_THREADS
from assetmap.models import (
    AssetClassificationTask,
    DnsRecord,
    NmapPort,
    ServiceAsset,
    WebProbeResult,
)
from assetmap.services.runtime.tool_resolver import ToolResolver


LIKELY_WEB_PORTS = {
    80,
    81,
    82,
    83,
    84,
    85,
    88,
    90,
    443,
    440,
    8000,
    8001,
    8008,
    8080,
    8081,
    8088,
    8089,
    8090,
    8092,
    8443,
    8888,
    8900,
    9000,
    9080,
    9081,
    9443,
    9980,
    18080,
    19080,
}
NON_WEB_SERVICES = {
    "ftp",
    "ssh",
    "smtp",
    "pop3",
    "imap",
    "mysql",
    "mssql",
    "ms-sql-s",
    "postgresql",
    "redis",
    "mongodb",
    "memcached",
    "ldap",
    "rdp",
    "ms-wbt-server",
    "smb",
}
NON_WEB_PORTS = {21, 22, 25, 110, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 9300, 11211, 27017}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _host_for_url(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _url(scheme: str, host: str, port: int) -> str:
    return f"{scheme}://{_host_for_url(host)}:{port}/"


def _normalise_probe_url(value: object) -> str | None:
    """Normalise httpx JSON fields back to the URL used as a checkpoint key."""
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}")
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return _url(scheme, host, port or (443 if scheme == "https" else 80))


def _quote(value: str) -> str:
    return subprocess.list2cmdline([value]) if os.name == "nt" else shlex.quote(value)


class AssetClassifierService:
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
        task = self._get_or_create_task(scan_task_id)
        task.status = "running"
        task.stage = "web_probe"
        task.started_at = task.started_at or _utcnow()
        task.error_message = None
        self.session.add(task)
        self.session.commit()
        try:
            ports = self._open_ports(scan_task_id)
            self._log(f"[classify] open ports: {len(ports)}")
            if rerun:
                self._clear_previous(scan_task_id)
            task.stage = "web_probe"
            self.session.add(task)
            self.session.commit()
            self._probe_web(scan_task_id, ports, rerun=rerun)
            self._log_web_probe_summary(scan_task_id)
            task.stage = "classify"
            self.session.add(task)
            self.session.commit()
            self._classify(scan_task_id, ports)
            self._log_service_summary(scan_task_id)
            task.status = "completed"
            task.stage = "completed"
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
            self._log(f"[classify] task {task.id} interrupted by user")
            raise
        except Exception as exc:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            raise

    def _get_or_create_task(self, scan_task_id: int) -> AssetClassificationTask:
        task = self.session.exec(
            select(AssetClassificationTask).where(AssetClassificationTask.scan_task_id == scan_task_id)
        ).first()
        if task:
            return task
        task = AssetClassificationTask(scan_task_id=scan_task_id)
        self.session.add(task)
        self.session.commit()
        self.session.refresh(task)
        return task

    def _clear_previous(self, scan_task_id: int) -> None:
        for table in (WebProbeResult, ServiceAsset):
            rows = self.session.exec(select(table).where(table.scan_task_id == scan_task_id)).all()
            for row in rows:
                self.session.delete(row)
        self.session.commit()

    def _open_ports(self, scan_task_id: int) -> list[NmapPort]:
        rows = self.session.exec(
            select(NmapPort).where(
                NmapPort.scan_task_id == scan_task_id,
                NmapPort.state == "open",
                NmapPort.protocol == "tcp",
            )
        ).all()
        return sorted(rows, key=lambda row: (row.target_ip, row.port))

    def _domains_by_ip(self, scan_task_id: int) -> dict[str, list[str]]:
        records = self.session.exec(
            select(DnsRecord).where(
                DnsRecord.scan_task_id == scan_task_id,
                DnsRecord.record_type.in_(["A", "AAAA"]),
            )
        ).all()
        mapping: dict[str, list[str]] = {}
        for record in records:
            mapping.setdefault(record.value, [])
            if record.fqdn not in mapping[record.value]:
                mapping[record.value].append(record.fqdn)
        return {ip: sorted(domains) for ip, domains in mapping.items()}

    def _fofa_hosts_by_port(self, scan_task_id: int) -> dict[tuple[str, int], list[str]]:
        rows = self.session.exec(select(NmapPort).where(NmapPort.scan_task_id == scan_task_id)).all()
        mapping: dict[tuple[str, int], list[str]] = {}
        for row in rows:
            host = self._fofa_hostname(row)
            if not host:
                continue
            key = (row.target_ip, row.port)
            mapping.setdefault(key, [])
            if host not in mapping[key]:
                mapping[key].append(host)
        return {key: sorted(value) for key, value in mapping.items()}

    def _fofa_hostname(self, port: NmapPort) -> str | None:
        payload = port.raw_payload or {}
        fofa = payload.get("fofa") if isinstance(payload.get("fofa"), dict) else payload
        host = str(fofa.get("host") or "").strip()
        if not host:
            return None
        parsed = urlparse(host if "://" in host else f"//{host}")
        hostname = (parsed.hostname or host).lower().rstrip(".")
        if not hostname or hostname == port.target_ip:
            return None
        return hostname

    def _probe_web(self, scan_task_id: int, ports: list[NmapPort], rerun: bool = False) -> None:
        domains_by_ip = self._domains_by_ip(scan_task_id)
        fofa_hosts_by_port = self._fofa_hosts_by_port(scan_task_id)
        primary_jobs: list[tuple[str, int, str, str]] = []
        saved_fallback_jobs: list[tuple[str, int, str, str]] = []
        seen: set[tuple[str, int, str, str]] = set()
        skipped_non_web = 0
        for port in ports:
            if not self._should_probe_web(port):
                skipped_non_web += 1
                continue
            hosts = self._probe_hosts(port, domains_by_ip, fofa_hosts_by_port)
            for host in hosts:
                primary, fallback = self._schemes_for_port(port.port)
                primary_result = None if rerun else self._httpx_checkpoint(
                    scan_task_id, port.target_ip, port.port, primary, host
                )
                if primary_result is None:
                    job = (port.target_ip, port.port, primary, host)
                    if job not in seen:
                        seen.add(job)
                        primary_jobs.append(job)
                    continue
                if self._should_try_fallback(primary_result):
                    fallback_result = self._httpx_checkpoint(scan_task_id, port.target_ip, port.port, fallback, host)
                    job = (port.target_ip, port.port, fallback, host)
                    if fallback_result is None and job not in seen:
                        seen.add(job)
                        saved_fallback_jobs.append(job)
        if not primary_jobs and not saved_fallback_jobs:
            if skipped_non_web:
                self._log(f"[classify] web probe skipped obvious non-web ports: {skipped_non_web}")
            return
        if skipped_non_web:
            self._log(f"[classify] web probe skipped obvious non-web ports: {skipped_non_web}")
        self._run_httpx_batch(scan_task_id, "primary", primary_jobs)

        fallback_jobs = list(saved_fallback_jobs)
        fallback_seen = set(fallback_jobs)
        for target_ip, port, scheme, host in primary_jobs:
            result = self._probe_record(scan_task_id, target_ip, port, scheme, host)
            if result and not self._should_try_fallback(result):
                continue
            fallback = self._schemes_for_port(port)[1]
            job = (target_ip, port, fallback, host)
            if job not in fallback_seen and not self._probe_exists(scan_task_id, *job):
                fallback_seen.add(job)
                fallback_jobs.append(job)
        if fallback_jobs:
            self._run_httpx_batch(scan_task_id, "fallback", fallback_jobs)

    def _should_probe_web(self, port: NmapPort) -> bool:
        service = (port.service or "").lower().strip()
        product = (port.product or "").lower().strip()
        if service in NON_WEB_SERVICES and port.port not in LIKELY_WEB_PORTS:
            return False
        if port.port in NON_WEB_PORTS and service in NON_WEB_SERVICES:
            return False
        if port.port in LIKELY_WEB_PORTS:
            return True
        payload = port.raw_payload or {}
        fofa = payload.get("fofa") if isinstance(payload.get("fofa"), dict) else payload
        fofa_host = str(fofa.get("host") or "")
        fofa_title = str(fofa.get("title") or "")
        fofa_server = str(fofa.get("server") or "")
        haystack = " ".join([service, product, fofa_host, fofa_title, fofa_server]).lower()
        return any(marker in haystack for marker in ("http", "https", "web", "nginx", "apache", "tomcat", "iis"))

    def _probe_hosts(
        self,
        port: NmapPort,
        domains_by_ip: dict[str, list[str]],
        fofa_hosts_by_port: dict[tuple[str, int], list[str]],
    ) -> list[str]:
        fofa_hosts = fofa_hosts_by_port.get((port.target_ip, port.port), [])
        dns_hosts = domains_by_ip.get(port.target_ip, [])
        if port.port in {80, 443}:
            candidates = [port.target_ip, *fofa_hosts, *dns_hosts]
        elif fofa_hosts:
            candidates = [port.target_ip, *fofa_hosts]
        else:
            candidates = [port.target_ip, *dns_hosts]
        hosts: list[str] = []
        for host in candidates:
            if host not in hosts:
                hosts.append(host)
        return hosts

    def _schemes_for_port(self, port: int) -> tuple[str, str]:
        return ("https", "http") if port in {443, 8443, 9443} else ("http", "https")

    def _should_try_fallback(self, result: WebProbeResult) -> bool:
        """A protocol-mismatch page is evidence, not a usable Web response."""
        if result.status != "responded":
            return True
        if result.scheme != "http" or result.http_status != 400:
            return False
        return self._is_protocol_mismatch(result)

    def _is_protocol_mismatch(self, result: WebProbeResult) -> bool:
        payload = (result.raw_headers or {}).get("httpx")
        payload_text = json.dumps(payload, ensure_ascii=False) if isinstance(payload, dict) else ""
        text = " ".join([result.title or "", result.error_message or "", payload_text]).lower()
        markers = (
            "plain http request was sent to https port",
            "plain http request to an https server",
            "speaking plain http to an ssl-enabled server port",
            "requires tls",
        )
        return any(marker in text for marker in markers)

    def _probe_exists(self, scan_task_id: int, target_ip: str, port: int, scheme: str, host: str) -> bool:
        return (
            self.session.exec(
                select(WebProbeResult).where(
                    WebProbeResult.scan_task_id == scan_task_id,
                    WebProbeResult.target_ip == target_ip,
                    WebProbeResult.port == port,
                    WebProbeResult.scheme == scheme,
                    WebProbeResult.host == host,
                )
            ).first()
            is not None
        )

    def _run_httpx_batch(
        self,
        scan_task_id: int,
        phase: str,
        jobs: list[tuple[str, int, str, str]],
    ) -> None:
        if not jobs:
            return
        output_dir = self.config.data_path("classify", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        input_file = output_dir / f"httpx_{phase}_input.txt"
        output_file = output_dir / f"httpx_{phase}.jsonl"
        job_by_url = {_url(scheme, host, port): (target_ip, port, scheme, host) for target_ip, port, scheme, host in jobs}
        input_file.write_text("\n".join(job_by_url) + "\n", encoding="utf-8")
        command = self._httpx_command(input_file, output_file)
        self._log(
            f"[httpx] {phase}: inputs={len(jobs)}, 内部并发={HTTPX_THREADS}, "
            f"限速={HTTPX_RATE_LIMIT}/秒, JSONL={output_file}"
        )
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        output_lines: list[str] = []
        parsed = 0
        with output_file.open("w", encoding="utf-8") as result_log:
            if process.stdout:
                for line in process.stdout:
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        payload = json.loads(text)
                    except json.JSONDecodeError:
                        output_lines.append(text)
                        self._log(f"[httpx] {phase} | {text}")
                        continue
                    if not isinstance(payload, dict):
                        continue
                    job = self._job_from_httpx_payload(payload, job_by_url)
                    if not job:
                        self._log(f"[httpx] {phase} | 忽略无法关联输入的响应")
                        continue
                    result_log.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    result_log.flush()
                    self._save_httpx_probe(scan_task_id, job, payload)
                    parsed += 1
                    self._log(self._httpx_result_message(phase, job, payload))
        exit_code = process.wait()
        if exit_code != 0:
            raise RuntimeError(f"httpx {phase} failed (exit={exit_code}): {' | '.join(output_lines[-5:])[:1000]}")
        for job in jobs:
            if self._probe_record(scan_task_id, *job) is None:
                self._save_httpx_failure(scan_task_id, job, "httpx returned no HTTP response")
        self._log(f"[httpx] {phase}: responded={parsed}, no_response={len(jobs) - parsed}")

    def _httpx_command(self, input_file: Path, output_file: Path) -> str:
        binary = ToolResolver(self.config.tools, self.config.config_dir).executable("httpx")
        if not binary:
            raise ValueError("ProjectDiscovery httpx not found. Install it and run `assetmap env-check`.")
        return self.config.tools.httpx_command.format(
            binary=_quote(str(binary)),
            input_file=_quote(str(input_file)),
            output_file=_quote(str(output_file)),
            timeout=max(1, int(self.config.web_probe.timeout_seconds)),
            user_agent_header=_quote(f"User-Agent: {self.config.web_probe.user_agent}"),
        )

    def _httpx_result_message(
        self,
        phase: str,
        job: tuple[str, int, str, str],
        payload: dict,
    ) -> str:
        _, port, scheme, host = job
        if scheme == "http" and self._payload_is_protocol_mismatch(payload):
            return f"[httpx] {phase} | {scheme}://{_host_for_url(host)}:{port} -> 协议不匹配，稍后改用 HTTPS"
        status = payload.get("status_code") or "?"
        title = str(payload.get("title") or "").strip().replace("\n", " ")[:80]
        suffix = f" | {title}" if title else ""
        return f"[httpx] {phase} | {scheme}://{_host_for_url(host)}:{port} -> HTTP {status}{suffix}"

    def _payload_is_protocol_mismatch(self, payload: dict) -> bool:
        text = json.dumps(payload, ensure_ascii=False).lower()
        markers = (
            "plain http request was sent to https port",
            "plain http request to an https server",
            "speaking plain http to an ssl-enabled server port",
            "requires tls",
        )
        return any(marker in text for marker in markers)

    def _save_httpx_results(
        self,
        scan_task_id: int,
        output_file: Path,
        job_by_url: dict[str, tuple[str, int, str, str]],
    ) -> int:
        if not output_file.exists():
            return 0
        saved = 0
        for line in output_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            job = self._job_from_httpx_payload(payload, job_by_url)
            if not job:
                continue
            self._save_httpx_probe(scan_task_id, job, payload)
            saved += 1
        return saved

    def _job_from_httpx_payload(
        self,
        payload: dict,
        job_by_url: dict[str, tuple[str, int, str, str]],
    ) -> tuple[str, int, str, str] | None:
        for field in ("input", "url", "final_url"):
            raw = str(payload.get(field) or "")
            if raw in job_by_url:
                return job_by_url[raw]
            normalised = _normalise_probe_url(raw)
            if normalised and normalised in job_by_url:
                return job_by_url[normalised]
        return None

    def _save_httpx_probe(self, scan_task_id: int, job: tuple[str, int, str, str], payload: dict) -> None:
        target_ip, port, scheme, host = job
        hashes = payload.get("hashes") if isinstance(payload.get("hashes"), dict) else {}
        technologies = payload.get("tech") or payload.get("technologies") or []
        if not isinstance(technologies, list):
            technologies = [str(technologies)]
        status_code = payload.get("status_code")
        try:
            status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        result = self._probe_record(scan_task_id, target_ip, port, scheme, host) or WebProbeResult(
            scan_task_id=scan_task_id, target_ip=target_ip, port=port, scheme=scheme, host=host, url=_url(scheme, host, port)
        )
        protocol_mismatch = scheme == "http" and status_code == 400 and self._payload_is_protocol_mismatch(payload)
        result.status = "protocol_mismatch" if protocol_mismatch else "responded"
        result.http_status = status_code
        result.final_url = str(payload.get("final_url") or payload.get("url") or result.url)
        result.title = str(payload.get("title") or "")[:300] or None
        result.server = str(payload.get("webserver") or payload.get("server") or "")[:300] or None
        result.content_type = str(payload.get("content_type") or "")[:300] or None
        result.body_hash = str(hashes.get("sha256") or payload.get("body_sha256") or payload.get("hash") or "") or None
        try:
            result.body_length = int(payload.get("content_length")) if payload.get("content_length") is not None else None
        except (TypeError, ValueError):
            result.body_length = None
        result.tech_stack = [str(item)[:120] for item in technologies]
        result.error_message = "HTTP request was sent to an HTTPS-only port" if protocol_mismatch else None
        result.raw_headers = {"probe_source": "projectdiscovery_httpx", "httpx": payload}
        self.session.add(result)
        self.session.commit()

    def _save_httpx_failure(self, scan_task_id: int, job: tuple[str, int, str, str], message: str) -> None:
        target_ip, port, scheme, host = job
        result = WebProbeResult(
            scan_task_id=scan_task_id,
            target_ip=target_ip,
            port=port,
            scheme=scheme,
            host=host,
            url=_url(scheme, host, port),
            status="failed",
            error_message=message,
            raw_headers={"probe_source": "projectdiscovery_httpx"},
        )
        self.session.add(result)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()

    def _probe_record(
        self,
        scan_task_id: int,
        target_ip: str,
        port: int,
        scheme: str,
        host: str,
    ) -> WebProbeResult | None:
        return self.session.exec(
            select(WebProbeResult).where(
                WebProbeResult.scan_task_id == scan_task_id,
                WebProbeResult.target_ip == target_ip,
                WebProbeResult.port == port,
                WebProbeResult.scheme == scheme,
                WebProbeResult.host == host,
            )
        ).first()

    def _httpx_checkpoint(
        self,
        scan_task_id: int,
        target_ip: str,
        port: int,
        scheme: str,
        host: str,
    ) -> WebProbeResult | None:
        """Keep only checkpoints created by the current ProjectDiscovery probe."""
        result = self._probe_record(scan_task_id, target_ip, port, scheme, host)
        if not result:
            return None
        evidence = result.raw_headers or {}
        if evidence.get("probe_source") == "projectdiscovery_httpx":
            # Results created by the first httpx migration used "responded"
            # for this page. Upgrade them before they can become Web assets.
            if result.status == "responded" and self._is_protocol_mismatch(result):
                result.status = "protocol_mismatch"
                result.error_message = "HTTP request was sent to an HTTPS-only port"
                self.session.add(result)
                self.session.commit()
            return result
        self.session.delete(result)
        self.session.commit()
        self._log(f"[httpx] 迁移旧检查点：{scheme}://{_host_for_url(host)}:{port}")
        return None

    def _classify(self, scan_task_id: int, ports: list[NmapPort]) -> None:
        probes = self.session.exec(select(WebProbeResult).where(WebProbeResult.scan_task_id == scan_task_id)).all()
        probes_by_port: dict[tuple[str, int], list[WebProbeResult]] = {}
        for probe in probes:
            probes_by_port.setdefault((probe.target_ip, probe.port), []).append(probe)
        for port in ports:
            rows = probes_by_port.get((port.target_ip, port.port), [])
            responded = [row for row in rows if row.status == "responded" and row.http_status is not None]
            if responded:
                self._save_web_asset(scan_task_id, port, responded)
            else:
                self._save_non_web_asset(scan_task_id, port, rows)

    def _save_web_asset(self, scan_task_id: int, port: NmapPort, probes: list[WebProbeResult]) -> None:
        service_asset = self._service_asset(scan_task_id, port) or ServiceAsset(
            scan_task_id=scan_task_id,
            target_ip=port.target_ip,
            protocol=port.protocol,
            port=port.port,
        )
        direct = [probe for probe in probes if probe.host == port.target_ip]
        domain = [probe for probe in probes if probe.host != port.target_ip]
        direct_hashes = {probe.body_hash for probe in direct if probe.body_hash}
        domain_hashes = {probe.body_hash for probe in domain if probe.body_hash}
        if domain and not direct:
            host_mode = "virtual_host"
        elif direct and domain_hashes and not domain_hashes.issubset(direct_hashes):
            host_mode = "mixed_vhost"
        elif direct:
            host_mode = "ip_site"
        else:
            host_mode = "unknown"
        best = self._best_probe(probes)
        app_name = self._app_name(best)
        domains = sorted({probe.host for probe in domain})
        service_asset.asset_kind = "web"
        service_asset.host_mode = host_mode
        service_asset.representative_url = best.final_url or best.url
        service_asset.domains = domains
        service_asset.http_status = best.http_status
        service_asset.title = best.title
        service_asset.app_name = app_name
        service_asset.evidence = {
            **(service_asset.evidence or {}),
            "responded_probe_count": len(probes),
            "direct_http": bool(direct),
            "domain_http": bool(domain),
            "body_hashes": sorted({probe.body_hash for probe in probes if probe.body_hash}),
            "tech_stack": best.tech_stack,
        }
        self._upsert_service_asset(service_asset)

    def _log_web_probe_summary(self, scan_task_id: int) -> None:
        rows = self.session.exec(select(WebProbeResult).where(WebProbeResult.scan_task_id == scan_task_id)).all()
        if not rows:
            self._log("[classify] web probe results: 0")
            return
        responded = [row for row in rows if row.status == "responded"]
        mismatches = [row for row in rows if row.status == "protocol_mismatch"]
        failed = len(rows) - len(responded) - len(mismatches)
        status_counts: dict[int, int] = {}
        for row in responded:
            if row.http_status is not None:
                status_counts[row.http_status] = status_counts.get(row.http_status, 0) + 1
        top_status = ", ".join(f"{status}={count}" for status, count in sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))[:8])
        self._log(
            f"[classify] web probe results: total={len(rows)}, responded={len(responded)}, "
            f"protocol_mismatch={len(mismatches)}, failed={failed}"
        )
        if top_status:
            self._log(f"[classify] http status summary: {top_status}")
        audit = self._write_web_probe_audit(scan_task_id, rows)
        self._log(f"[classify] web probe audit: {audit}")

    def _log_service_summary(self, scan_task_id: int) -> None:
        rows = self.session.exec(select(ServiceAsset).where(ServiceAsset.scan_task_id == scan_task_id)).all()
        web = sum(1 for row in rows if row.asset_kind == "web")
        non_web = sum(1 for row in rows if row.asset_kind == "non_web")
        unknown = len(rows) - web - non_web
        self._log(f"[classify] service assets: total={len(rows)}, web={web}, non_web={non_web}, unknown={unknown}")
        audit = self._write_service_classification_audit(scan_task_id, rows)
        self._log(f"[classify] service classification audit: {audit}")

    def _write_web_probe_audit(self, scan_task_id: int, rows: list[WebProbeResult]) -> Path:
        output_dir = self.config.data_path("classify", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        status_counts: dict[str, int] = {}
        error_counts: dict[str, int] = {}
        protocol_mismatch_count = 0
        protocol_mismatches = []
        failed_samples = []
        for row in rows:
            if row.status == "responded" and row.http_status is not None:
                key = str(row.http_status)
                status_counts[key] = status_counts.get(key, 0) + 1
            elif row.status == "failed":
                error = (row.error_message or "unknown")[:300]
                error_counts[error] = error_counts.get(error, 0) + 1
                if len(failed_samples) < 30:
                    failed_samples.append(
                        {
                            "target_ip": row.target_ip,
                            "port": row.port,
                            "scheme": row.scheme,
                            "host": row.host,
                            "error": error,
                        }
                    )
            elif row.status == "protocol_mismatch":
                protocol_mismatch_count += 1
                if len(protocol_mismatches) < 30:
                    protocol_mismatches.append(
                        {
                            "target_ip": row.target_ip,
                            "port": row.port,
                            "scheme": row.scheme,
                            "host": row.host,
                            "message": row.error_message,
                        }
                    )
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "total": len(rows),
            "responded": sum(1 for row in rows if row.status == "responded"),
            "protocol_mismatch": protocol_mismatch_count,
            "failed": sum(1 for row in rows if row.status == "failed"),
            "http_status_counts": dict(sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))),
            "error_counts": dict(sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:20]),
            "failed_samples": failed_samples,
            "protocol_mismatch_samples": protocol_mismatches,
        }
        path = output_dir / "web_probe_audit.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _write_service_classification_audit(self, scan_task_id: int, rows: list[ServiceAsset]) -> Path:
        output_dir = self.config.data_path("classify", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        kind_counts: dict[str, int] = {}
        host_mode_counts: dict[str, int] = {}
        passive_fofa_count = 0
        service_rows = []
        review_candidates = []
        for row in sorted(rows, key=lambda item: (item.target_ip, item.port, item.protocol)):
            kind = row.asset_kind or "unknown"
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
            host_mode = row.host_mode or "unknown"
            host_mode_counts[host_mode] = host_mode_counts.get(host_mode, 0) + 1
            evidence = row.evidence or {}
            if host_mode == "passive_fofa" or evidence.get("passive_web_source") == "fofa":
                passive_fofa_count += 1
            service_rows.append(
                {
                    "endpoint": f"{row.target_ip}:{row.port}",
                    "target_ip": row.target_ip,
                    "protocol": row.protocol,
                    "port": row.port,
                    "asset_kind": kind,
                    "host_mode": host_mode,
                    "representative_url": row.representative_url,
                    "domains": row.domains,
                    "http_status": row.http_status,
                    "title": row.title,
                    "app_name": row.app_name,
                    "service": row.service,
                    "product": row.product,
                    "version": row.version,
                    "evidence_keys": sorted(evidence.keys()),
                    "passive_fofa": host_mode == "passive_fofa" or evidence.get("passive_web_source") == "fofa",
                    "active_probe_failed": bool(evidence.get("active_probe_failed")),
                }
            )
            if kind != "web" and self._service_asset_looks_web_like(row):
                review_candidates.append(
                    {
                        "target_ip": row.target_ip,
                        "port": row.port,
                        "asset_kind": kind,
                        "service": row.service,
                        "product": row.product,
                        "evidence": row.evidence,
                    }
                )
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "total": len(rows),
            "kind_counts": dict(sorted(kind_counts.items())),
            "host_mode_counts": dict(sorted(host_mode_counts.items())),
            "passive_fofa_count": passive_fofa_count,
            "review_candidate_count": len(review_candidates),
            "web_like_review_candidates": review_candidates,
            "services": service_rows,
        }
        path = output_dir / "service_classification_audit.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _service_asset_looks_web_like(self, row: ServiceAsset) -> bool:
        text = " ".join(str(value or "") for value in (row.service, row.product, row.title, row.app_name, row.representative_url)).lower()
        if row.port in LIKELY_WEB_PORTS:
            return True
        return any(marker in text for marker in ("http", "https", "nginx", "apache", "tomcat", "iis", "websphere", "weblogic", "web"))

    def _save_non_web_asset(self, scan_task_id: int, port: NmapPort, probes: list[WebProbeResult]) -> None:
        passive = self._passive_web_evidence(port)
        if passive:
            service_asset = self._service_asset(scan_task_id, port) or ServiceAsset(
                scan_task_id=scan_task_id,
                target_ip=port.target_ip,
                protocol=port.protocol,
                port=port.port,
            )
            service_asset.asset_kind = "web"
            service_asset.host_mode = "passive_fofa"
            service_asset.service = port.service
            service_asset.product = port.product or passive.get("server")
            service_asset.version = port.version
            service_asset.representative_url = passive["url"]
            service_asset.domains = [passive["hostname"]] if passive.get("hostname") and passive["hostname"] != port.target_ip else []
            service_asset.title = passive.get("title") or None
            service_asset.app_name = passive.get("title") or passive.get("server") or None
            service_asset.evidence = {
                **(service_asset.evidence or {}),
                "passive_web_source": "fofa",
                "passive_web_host": passive.get("host", ""),
                "passive_web_protocol": passive.get("protocol", ""),
                "active_probe_failed": True,
                "web_probe_errors": [
                    {"scheme": row.scheme, "host": row.host, "error": row.error_message}
                    for row in probes[:20]
                ],
            }
            self._upsert_service_asset(service_asset)
            return
        service_asset = self._service_asset(scan_task_id, port) or ServiceAsset(
            scan_task_id=scan_task_id,
            target_ip=port.target_ip,
            protocol=port.protocol,
            port=port.port,
            service=port.service,
            product=port.product,
            version=port.version,
        )
        service_asset.asset_kind = "non_web"
        service_asset.host_mode = "none"
        service_asset.evidence = {
            **(service_asset.evidence or {}),
            "web_probe_errors": [
                {"scheme": row.scheme, "host": row.host, "error": row.error_message}
                for row in probes[:20]
            ],
        }
        self._upsert_service_asset(service_asset)

    def _passive_web_evidence(self, port: NmapPort) -> dict[str, str] | None:
        payload = port.raw_payload or {}
        fofa = payload.get("fofa") if isinstance(payload.get("fofa"), dict) else payload
        raw = fofa.get("raw") if isinstance(fofa.get("raw"), dict) else {}
        host = str(fofa.get("host") or raw.get("host") or "").strip()
        protocol = str(raw.get("protocol") or fofa.get("protocol") or "").strip().lower()
        title = str(fofa.get("title") or raw.get("title") or "").strip()
        server = str(fofa.get("server") or raw.get("server") or "").strip()
        if not host:
            return None
        if protocol not in {"http", "https"} and not host.lower().startswith(("http://", "https://")):
            haystack = " ".join([protocol, title, server, port.service or "", port.product or ""]).lower()
            if not any(marker in haystack for marker in ("http", "https", "nginx", "apache", "tomcat", "iis", "websphere", "weblogic", "web")):
                return None
        url = self._passive_web_url(host, protocol or ("https" if port.port in {443, 8443, 9443} else "http"), port.port)
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        return {
            "url": url,
            "host": host,
            "hostname": hostname,
            "protocol": parsed.scheme,
            "title": title,
            "server": server,
        }

    def _passive_web_url(self, host: str, protocol: str, port: int) -> str:
        value = host.strip()
        if "://" not in value:
            value = f"{protocol}://{value}"
        parsed = urlparse(value)
        scheme = parsed.scheme if parsed.scheme in {"http", "https"} else protocol
        hostname = parsed.hostname or host.split(":", 1)[0]
        try:
            actual_port = parsed.port or port
        except ValueError:
            # FOFA host fields are external input. Retain the verified Nmap
            # port instead of letting an invalid textual port abort classify.
            actual_port = port
        default_port = 443 if scheme == "https" else 80
        netloc = _host_for_url(hostname.lower().rstrip("."))
        if actual_port and actual_port != default_port:
            netloc = f"{netloc}:{actual_port}"
        path = parsed.path or "/"
        return f"{scheme}://{netloc}{path}"

    def _service_asset(self, scan_task_id: int, port: NmapPort) -> ServiceAsset | None:
        return self.session.exec(
            select(ServiceAsset).where(
                ServiceAsset.scan_task_id == scan_task_id,
                ServiceAsset.target_ip == port.target_ip,
                ServiceAsset.protocol == port.protocol,
                ServiceAsset.port == port.port,
            )
        ).first()

    def _best_probe(self, probes: list[WebProbeResult]) -> WebProbeResult:
        return sorted(
            probes,
            key=lambda row: (
                0 if row.host != row.target_ip else 1,
                0 if row.http_status and 200 <= row.http_status < 400 else 1,
                len(row.title or "") * -1,
            ),
        )[0]

    def _app_name(self, probe: WebProbeResult) -> str | None:
        if probe.tech_stack:
            return ", ".join(probe.tech_stack[:3])
        if probe.title:
            parsed = urlparse(probe.final_url or probe.url)
            return f"{probe.title} ({parsed.netloc})"
        return probe.server or probe.powered_by

    def _upsert_service_asset(self, asset: ServiceAsset) -> None:
        row = self.session.exec(
            select(ServiceAsset).where(
                ServiceAsset.scan_task_id == asset.scan_task_id,
                ServiceAsset.target_ip == asset.target_ip,
                ServiceAsset.protocol == asset.protocol,
                ServiceAsset.port == asset.port,
            )
        ).first()
        if row:
            for key, value in asset.model_dump(exclude={"id"}).items():
                setattr(row, key, value)
            row.observed_at = _utcnow()
            self.session.add(row)
        else:
            self.session.add(asset)
        self.session.commit()
