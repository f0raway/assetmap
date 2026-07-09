from __future__ import annotations

import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import httpx
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig
from assetmap.models import (
    AssetClassificationTask,
    DnsRecord,
    NmapPort,
    ServiceAsset,
    WebProbeResult,
)
from assetmap.services.nmap_scan import _quote, _safe_ip
from assetmap.services.tool_resolver import ToolResolver


TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TAG_PATTERN = re.compile(r"<[^>]+>")
WHITESPACE_PATTERN = re.compile(r"\s+")
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


def _title(text: str) -> str | None:
    match = TITLE_PATTERN.search(text)
    if not match:
        return None
    value = WHITESPACE_PATTERN.sub(" ", TAG_PATTERN.sub("", match.group(1))).strip()
    return value[:300] or None


def _hash_body(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _tech_stack(headers: dict[str, str], body_text: str, title: str | None) -> list[str]:
    haystack = f"{title or ''}\n{body_text[:20000]}".lower()
    found: list[str] = []
    for header_name in ("server", "x-powered-by", "x-generator"):
        value = headers.get(header_name)
        if value:
            found.append(value[:120])
    markers = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal-settings-json"],
        "Joomla": ["content=\"joomla"],
        "Vue": ["__vue__", "vue.js"],
        "React": ["reactroot", "__react"],
        "Swagger": ["swagger-ui", "api-docs"],
        "Spring": ["whitelabel error page", "jsessionid"],
        "ASP.NET": ["asp.net", "__viewstate"],
        "PHP": ["phpsessid"],
        "ThinkPHP": ["thinkphp"],
        "RuoYi": ["ruoyi", "若依"],
        "宝塔": ["宝塔", "bt.cn"],
        "泛微 OA": ["weaver", "ecology"],
        "致远 OA": ["seeyon"],
        "用友": ["yonyou", "用友"],
        "金蝶": ["kingdee", "金蝶"],
    }
    for name, needles in markers.items():
        if any(needle in haystack for needle in needles):
            found.append(name)
    deduped: list[str] = []
    for item in found:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


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
            task.stage = "service_detect"
            self.session.add(task)
            self.session.commit()
            self._detect_services(scan_task_id, ports, rerun=rerun)
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
        jobs: list[tuple[str, int, str, str]] = []
        seen_jobs: set[tuple[str, int, str, str]] = set()
        skipped_non_web = 0
        for port in ports:
            if not self._should_probe_web(port):
                skipped_non_web += 1
                continue
            hosts = self._probe_hosts(scan_task_id, port, domains_by_ip, fofa_hosts_by_port, rerun=rerun)
            for host in hosts:
                for scheme in self._schemes_for_port(port.port):
                    if not rerun and self._probe_exists(scan_task_id, port.target_ip, port.port, scheme, host):
                        continue
                    job = (port.target_ip, port.port, scheme, host)
                    if job in seen_jobs:
                        continue
                    seen_jobs.add(job)
                    jobs.append(job)
        if not jobs:
            if skipped_non_web:
                self._log(f"[classify] web probe skipped obvious non-web ports: {skipped_non_web}")
            return
        if skipped_non_web:
            self._log(f"[classify] web probe skipped obvious non-web ports: {skipped_non_web}")
        self._log(f"[classify] web probe jobs: {len(jobs)}")
        workers = min(max(1, self.config.web_probe.max_workers), len(jobs))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._probe_one, scan_task_id, target_ip, port, scheme, host)
                for target_ip, port, scheme, host in jobs
            ]
            for future in as_completed(futures):
                future.result()

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
        scan_task_id: int,
        port: NmapPort,
        domains_by_ip: dict[str, list[str]],
        fofa_hosts_by_port: dict[tuple[str, int], list[str]],
        rerun: bool = False,
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
        batch_size = max(1, self.config.web_probe.max_domains_per_ip) + 1
        if rerun:
            return hosts[:batch_size]
        unprobed = [
            host
            for host in hosts
            if any(
                not self._probe_exists(scan_task_id, port.target_ip, port.port, scheme, host)
                for scheme in self._schemes_for_port(port.port)
            )
        ]
        return unprobed[:batch_size]

    def _schemes_for_port(self, port: int) -> tuple[str, str]:
        return ("https", "http") if port in {443, 8443, 9443} else ("http", "https")

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

    def _probe_one(self, scan_task_id: int, target_ip: str, port: int, scheme: str, host: str) -> None:
        headers = {
            "User-Agent": self.config.web_probe.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
        }
        url = _url(scheme, host, port)
        result = WebProbeResult(
            scan_task_id=scan_task_id,
            target_ip=target_ip,
            port=port,
            scheme=scheme,
            host=host,
            url=url,
        )
        try:
            with httpx.Client(
                timeout=self.config.web_probe.timeout_seconds,
                follow_redirects=True,
                verify=False,
                trust_env=False,
                headers=headers,
            ) as client:
                response = client.get(url)
            content = response.content[: self.config.web_probe.max_body_bytes]
            text = content.decode(response.encoding or "utf-8", errors="replace")
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            result.status = "responded"
            result.http_status = response.status_code
            result.final_url = str(response.url)
            result.title = _title(text)
            result.server = response_headers.get("server")
            result.powered_by = response_headers.get("x-powered-by")
            result.content_type = response_headers.get("content-type")
            result.body_hash = _hash_body(content)
            result.body_length = len(response.content)
            result.tech_stack = _tech_stack(response_headers, text, result.title)
            result.raw_headers = dict(response.headers)
        except Exception as exc:
            result.status = "failed"
            result.error_message = str(exc)[:1000]
        with Session(self.session.get_bind()) as session:
            session.add(result)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()

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
        failed = len(rows) - len(responded)
        status_counts: dict[int, int] = {}
        for row in responded:
            if row.http_status is not None:
                status_counts[row.http_status] = status_counts.get(row.http_status, 0) + 1
        top_status = ", ".join(f"{status}={count}" for status, count in sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))[:8])
        self._log(f"[classify] web probe results: total={len(rows)}, responded={len(responded)}, failed={failed}")
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
        output_dir = Path("data") / "classify" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        status_counts: dict[str, int] = {}
        error_counts: dict[str, int] = {}
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
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "total": len(rows),
            "responded": sum(1 for row in rows if row.status == "responded"),
            "failed": sum(1 for row in rows if row.status == "failed"),
            "http_status_counts": dict(sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))),
            "error_counts": dict(sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))[:20]),
            "failed_samples": failed_samples,
        }
        path = output_dir / "web_probe_audit.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _write_service_classification_audit(self, scan_task_id: int, rows: list[ServiceAsset]) -> Path:
        output_dir = Path("data") / "classify" / f"task_{scan_task_id}"
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
        actual_port = parsed.port or port
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

    def _detect_services(self, scan_task_id: int, ports: list[NmapPort], rerun: bool = False) -> None:
        grouped: dict[str, list[NmapPort]] = {}
        for port in ports:
            grouped.setdefault(port.target_ip, []).append(port)
        if grouped:
            self._log(f"[classify] high-intensity -sV targets: {len(grouped)} hosts")
        for target_ip, host_ports in grouped.items():
            existing = [
                self._service_asset(scan_task_id, port)
                for port in host_ports
            ]
            if not rerun and existing and all(row and row.evidence.get("service_detect_command") for row in existing):
                self._log(f"[classify] skip service detect: {target_ip}")
                continue
            self._detect_host_services(scan_task_id, target_ip, host_ports)

    def _detect_host_services(self, scan_task_id: int, target_ip: str, ports: list[NmapPort]) -> None:
        executable = ToolResolver(self.config.tools).nmap_executable()
        if not executable:
            for port in ports:
                self._upsert_service_asset(
                    ServiceAsset(
                        scan_task_id=scan_task_id,
                        target_ip=port.target_ip,
                        protocol=port.protocol,
                        port=port.port,
                        asset_kind="unknown",
                        service=port.service,
                        product=port.product,
                        version=port.version,
                        evidence={"service_detect_error": "nmap executable not found"},
                    )
                )
            return
        output_dir = Path("data") / "nmap" / f"task_{scan_task_id}" / "service_detect"
        output_dir.mkdir(parents=True, exist_ok=True)
        port_list = ",".join(str(port.port) for port in sorted(ports, key=lambda item: item.port))
        stem = f"{_safe_ip(target_ip)}_{port_list.replace(',', '_')}"
        xml_output = output_dir / f"{stem}.xml"
        normal_output = output_dir / f"{stem}.txt"
        command = self.config.tools.nmap_service_detect_command.format(
            binary=_quote(str(executable)),
            target=_quote(target_ip),
            port=port_list,
            ports=port_list,
            xml_output=_quote(str(xml_output)),
            normal_output=_quote(str(normal_output)),
            output_dir=_quote(str(output_dir)),
        )
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.tools.nmap_timeout_seconds,
            )
            parsed = self._parse_service_xml(xml_output) if xml_output.exists() else {}
            for port in ports:
                details = parsed.get(port.port, {})
                self._upsert_service_asset(
                    ServiceAsset(
                        scan_task_id=scan_task_id,
                        target_ip=target_ip,
                        protocol=port.protocol,
                        port=port.port,
                        asset_kind="unknown",
                        service=details.get("service") or port.service,
                        product=details.get("product") or port.product,
                        version=details.get("version") or port.version,
                        evidence={
                            "service_detect_command": command,
                            "service_detect_exit_code": proc.returncode,
                            "service_detect_output": str(normal_output),
                        },
                    )
                )
        except Exception as exc:
            for port in ports:
                self._upsert_service_asset(
                    ServiceAsset(
                        scan_task_id=scan_task_id,
                        target_ip=target_ip,
                        protocol=port.protocol,
                        port=port.port,
                        asset_kind="unknown",
                        service=port.service,
                        product=port.product,
                        version=port.version,
                        evidence={"service_detect_error": str(exc)[:1000]},
                    )
                )

    def _parse_service_xml(self, path: Path) -> dict[int, dict[str, str | None]]:
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            return {}
        result: dict[int, dict[str, str | None]] = {}
        for port in root.findall(".//port"):
            port_id = int(port.attrib.get("portid", "0"))
            service = port.find("service")
            if service is None:
                continue
            result[port_id] = {
                "service": service.attrib.get("name"),
                "product": service.attrib.get("product"),
                "version": service.attrib.get("version"),
            }
        return result
