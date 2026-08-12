from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import dns.exception
import dns.resolver
import httpx
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AiConfig, AppConfig
from assetmap.models import (
    AiAnalysis,
    CompanyAssetLink,
    DnsQueryStatus,
    DnsRecord,
    InternetAsset,
    SubdomainEnumerationTask,
    SubdomainRecord,
    SubdomainToolRun,
)
from assetmap.services.identification.ai_client import chat_completion
from assetmap.services.runtime.tool_resolver import ToolResolver
from assetmap.utils import stable_hash


MAIN_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")
SUBDOMAIN_RECORD_TYPES = ("A", "AAAA", "CNAME")
SUPPORTED_SUBDOMAIN_TOOLS = {"subfinder", "dnsx"}
INTERRUPTED_EXIT_CODES = {3221225786, -1073741510}
INTERRUPTED_ERROR_MARKERS = ("^c", "keyboardinterrupt", "interrupted", "ctrl+c", "control-c")
DNS_AI_BATCH_MAX_RECORDS = 1000
DNS_AI_BATCH_MAX_CHARS = 45000
DOH_ENDPOINTS = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)
DOH_RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "domain"


def _quote(value: str) -> str:
    """Quote runtime values before interpolating them into a configured shell command."""
    if os.name == "nt":
        return subprocess.list2cmdline([value])
    return shlex.quote(value)


def normalize_hostname(value: str) -> str | None:
    text = value.strip().lower().rstrip(".")
    text = re.sub(r"^https?://", "", text)
    text = text.split("/")[0].split(":")[0].strip()
    if not text or "." not in text:
        return None
    if not re.fullmatch(r"[a-z0-9*_.-]+", text):
        return None
    if text.startswith("*."):
        text = text[2:]
    return text


def _is_subdomain(hostname: str, root_domain: str) -> bool:
    return hostname != root_domain and hostname.endswith(f".{root_domain}")


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and ip not in ipaddress.ip_network("198.18.0.0/15")


def _record_type_for_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return "AAAA" if ip.version == 6 else "A"


def _tool_line_hostname(line: str) -> str | None:
    first = line.split("=>", 1)[0].strip()
    return normalize_hostname(first)


def _tool_line_dns_values(line: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for token in line.split("=>")[1:]:
        text = token.strip()
        if not text:
            continue
        if text.upper().startswith("CNAME "):
            cname = normalize_hostname(text.split(None, 1)[1])
            if cname:
                values.append(("CNAME", cname))
            continue
        record_type = _record_type_for_ip(text)
        if record_type and _is_public_ip(text):
            values.append((record_type, text))
    return values


class SubdomainService:
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

    def run(
        self,
        scan_task_id: int,
        run_ai: bool = True,
        rerun_tools: bool = False,
        rerun_dns: bool = False,
    ) -> int:
        task = self._get_or_create_task(scan_task_id)
        task.status = "running"
        task.stage = "enumerating"
        task.started_at = task.started_at or _utcnow()
        task.error_message = None
        self.session.add(task)
        self.session.commit()
        try:
            self._reset_stale_running_tool_runs(scan_task_id)
            root_domains = self._root_domains(scan_task_id)
            self._log(f"[subdomain] root domains: {len(root_domains)}")
            self._run_enumerators(scan_task_id, root_domains, rerun_tools=rerun_tools)
            self._log_tool_summary(scan_task_id)
            if rerun_dns:
                self._clear_dns_results(scan_task_id)
            self._parse_tool_outputs(scan_task_id, root_domains)
            self._log_discovered_subdomains(scan_task_id)

            task.stage = "dns_main"
            self.session.add(task)
            self.session.commit()
            self._resolve_domains(scan_task_id, root_domains, MAIN_RECORD_TYPES)

            task.stage = "dns_subdomains"
            self.session.add(task)
            self.session.commit()
            subdomains = self._subdomains(scan_task_id)
            self._log(f"[dns] subdomains: {len(subdomains)}")
            self._resolve_domains(scan_task_id, subdomains, SUBDOMAIN_RECORD_TYPES)
            self._log_dns_coverage_summary(scan_task_id, root_domains)
            audit = self._write_subdomain_audit(scan_task_id, root_domains)
            self._log(f"[subdomain] audit: {audit}")

            if run_ai and self.config.ai.enabled:
                task.stage = "ai"
                self.session.add(task)
                self.session.commit()
                self._run_ai_analysis(scan_task_id)

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
            self._log(f"[subdomain] task {task.id} interrupted by user")
            raise
        except Exception as exc:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            raise

    def _clear_dns_results(self, scan_task_id: int) -> None:
        dns_records = self.session.exec(select(DnsRecord).where(DnsRecord.scan_task_id == scan_task_id)).all()
        dns_statuses = self.session.exec(select(DnsQueryStatus).where(DnsQueryStatus.scan_task_id == scan_task_id)).all()
        removed_records = 0
        for row in dns_records:
            if (row.raw_payload or {}).get("kind") == "manual_ip":
                continue
            self.session.delete(row)
            removed_records += 1
        for row in dns_statuses:
            self.session.delete(row)
        if dns_records or dns_statuses:
            self.session.commit()
            kept_manual = len(dns_records) - removed_records
            self._log(
                f"[dns] rerun requested: cleared records={removed_records}, "
                f"kept_manual_ips={kept_manual}, statuses={len(dns_statuses)}"
            )

    def _reset_stale_running_tool_runs(self, scan_task_id: int) -> None:
        rows = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == scan_task_id,
                SubdomainToolRun.status == "running",
            )
        ).all()
        for row in rows:
            row.status = "pending"
            row.error_message = "Recovered from previous interrupted run"
            self.session.add(row)
        if rows:
            self.session.commit()

    def _get_or_create_task(self, scan_task_id: int) -> SubdomainEnumerationTask:
        task = self.session.exec(
            select(SubdomainEnumerationTask).where(
                SubdomainEnumerationTask.scan_task_id == scan_task_id
            )
        ).first()
        if task:
            return task
        task = SubdomainEnumerationTask(scan_task_id=scan_task_id)
        self.session.add(task)
        self.session.commit()
        self.session.refresh(task)
        return task

    def _root_domains(self, scan_task_id: int) -> list[str]:
        assets = self.session.exec(
            select(InternetAsset)
            .join(CompanyAssetLink, CompanyAssetLink.asset_id == InternetAsset.id)
            .where(
                CompanyAssetLink.task_id == scan_task_id,
                InternetAsset.asset_type == "icp_domain",
            )
        ).all()
        domains = {
            domain
            for asset in assets
            if (domain := normalize_hostname(asset.normalized_identifier))
        }
        return sorted(domains, key=lambda value: (-len(value), value))

    def _subdomains(self, scan_task_id: int) -> list[str]:
        rows = self.session.exec(
            select(SubdomainRecord).where(SubdomainRecord.scan_task_id == scan_task_id)
        ).all()
        return sorted({row.fqdn for row in rows})

    def _log_discovered_subdomains(self, scan_task_id: int) -> None:
        subdomains = self._subdomains(scan_task_id)
        output_dir = Path("data") / "subdomains" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "discovered_subdomains.txt"
        path.write_text("\n".join(subdomains) + ("\n" if subdomains else ""), encoding="utf-8")
        self._log(f"[subdomain] discovered subdomains before DNS: {len(subdomains)}")
        for index in range(0, len(subdomains), 20):
            self._log(f"[subdomain] discovered: {', '.join(subdomains[index:index + 20])}")
        self._log(f"[subdomain] discovered subdomain list: {path}")

    def _binary_path(self, tool_name: str) -> str:
        suffix = ".exe" if __import__("platform").system().lower().startswith("windows") else ""
        path = Path(self.config.tools.tools_dir) / tool_name / f"{tool_name}{suffix}"
        resolved = ToolResolver(self.config.tools).executable(tool_name)
        if resolved:
            return str(resolved)
        return str(path) if path.exists() else tool_name

    def _format_command(self, template: str, tool_name: str, domain: str, output: Path) -> str:
        return template.format(
            binary=_quote(self._binary_path(tool_name)),
            domain=_quote(domain),
            output=_quote(str(output)),
            wordlist=_quote(self.config.tools.wordlist),
        )

    def _run_enumerators(self, scan_task_id: int, root_domains: list[str], rerun_tools: bool = False) -> None:
        jobs: list[SubdomainToolRun] = []
        output_root = Path("data") / "subdomains" / f"task_{scan_task_id}"
        enabled_tools = self._enabled_subdomain_tools()
        self._log_subfinder_provider_hint(enabled_tools)
        for domain in root_domains:
            for tool_name, template in enabled_tools:
                output = output_root / _safe_name(domain) / f"{tool_name}.txt"
                output.parent.mkdir(parents=True, exist_ok=True)
                run = self._get_or_create_tool_run(
                    scan_task_id,
                    domain,
                    tool_name,
                    self._format_command(template, tool_name, domain, output),
                    output,
                )
                if run.status == "completed" and not rerun_tools:
                    self._log(f"[subdomain] skip completed {tool_name}: {domain}")
                    continue
                if run.status == "failed" and not rerun_tools:
                    if self._is_interrupted_tool_run(run):
                        self._log(f"[subdomain] recover interrupted {tool_name}: {domain}")
                        run.error_message = "Recovered from previous Ctrl+C interruption"
                    else:
                        self._log(f"[subdomain] retry failed {tool_name}: {domain}")
                    run.status = "pending"
                    run.exit_code = None
                    self.session.add(run)
                    self.session.commit()
                    jobs.append(run)
                    continue
                if run.status == "running" and not rerun_tools:
                    self._log(f"[subdomain] skip running {tool_name}: {domain} (use --rerun-tools to restart)")
                    continue
                if rerun_tools and run.status in {"completed", "failed"}:
                    self._log(f"[subdomain] rerun requested {tool_name}: {domain}")
                    run.status = "pending"
                    self.session.add(run)
                    self.session.commit()
                jobs.append(run)

        if not jobs:
            return
        self._log(f"[subdomain] running {len(jobs)} tool jobs in parallel")
        workers = min(max(1, self.config.dns.max_workers), len(jobs), 8)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._run_tool_job, run.id) for run in jobs if run.id]
            for future in as_completed(futures):
                future.result()

    def _log_subfinder_provider_hint(self, enabled_tools: list[tuple[str, str]]) -> None:
        if not any(tool_name == "subfinder" for tool_name, _ in enabled_tools):
            return
        self._log(
            "[subfinder] 提示：未配置 provider API Key 仍可运行，但被动子域名覆盖率会明显下降。"
        )
        self._log(
            "[subfinder] 建议：在 macOS/Linux 的 ~/.config/subfinder/provider-config.yaml 配置自己的 provider Key，"
            "或通过 -pc / SUBFINDER_PROVIDER_CONFIG 指定文件；可优先配置 Chaos、Censys、FOFA、GitHub、"
            "SecurityTrails、Shodan、ZoomEye、VirusTotal。请勿在终端、报告或仓库中粘贴 Key。"
        )

    def _is_interrupted_tool_run(self, run: SubdomainToolRun) -> bool:
        if run.exit_code in INTERRUPTED_EXIT_CODES:
            return True
        text = " ".join(
            str(value or "")
            for value in (run.error_message, run.stderr, run.stdout)
        ).strip().lower()
        return any(marker in text for marker in INTERRUPTED_ERROR_MARKERS)

    def _enabled_subdomain_tools(self) -> list[tuple[str, str]]:
        templates = {
            "subfinder": self.config.tools.subfinder_command,
            "dnsx": self.config.tools.dnsx_command,
        }
        enabled: list[tuple[str, str]] = []
        for tool_name in self.config.tools.subdomain_tools_enabled:
            normalized = tool_name.lower().strip()
            if normalized not in SUPPORTED_SUBDOMAIN_TOOLS:
                self._log(f"[subdomain] skip unsupported tool in config: {tool_name}")
                continue
            enabled.append((normalized, templates[normalized]))
        return enabled

    def _enabled_subdomain_tool_names(self) -> list[str]:
        names = []
        for tool_name in self.config.tools.subdomain_tools_enabled:
            normalized = tool_name.lower().strip()
            if normalized in SUPPORTED_SUBDOMAIN_TOOLS and normalized not in names:
                names.append(normalized)
        return names or ["__none__"]

    def _get_or_create_tool_run(
        self,
        scan_task_id: int,
        root_domain: str,
        tool_name: str,
        command: str,
        output: Path,
    ) -> SubdomainToolRun:
        run = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == scan_task_id,
                SubdomainToolRun.root_domain == root_domain,
                SubdomainToolRun.tool_name == tool_name,
            )
        ).first()
        if run:
            command_changed = run.command != command or run.output_path != str(output)
            run.command = command
            run.output_path = str(output)
            if command_changed and run.status not in {"completed", "failed"}:
                run.status = "pending"
            self.session.add(run)
            self.session.commit()
            return run
        run = SubdomainToolRun(
            scan_task_id=scan_task_id,
            root_domain=root_domain,
            tool_name=tool_name,
            command=command,
            output_path=str(output),
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def _run_tool_job(self, run_id: int) -> None:
        with Session(self.session.get_bind()) as session:
            run = session.get(SubdomainToolRun, run_id)
            if not run:
                return
            run.status = "running"
            run.started_at = _utcnow()
            run.error_message = None
            session.add(run)
            session.commit()
            self._log(f"[subdomain] {run.tool_name} -> {run.root_domain}")
            try:
                proc = subprocess.run(
                    run.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.config.tools.subdomain_tool_timeout_seconds,
                )
                run.exit_code = proc.returncode
                run.stdout = proc.stdout[-20000:]
                run.stderr = proc.stderr[-20000:]
                run.status = "completed" if proc.returncode == 0 else "failed"
                if proc.returncode != 0:
                    run.error_message = proc.stderr[-2000:] or proc.stdout[-2000:]
            except Exception as exc:
                run.status = "failed"
                run.error_message = str(exc)
            run.finished_at = _utcnow()
            session.add(run)
            session.commit()

    def _log_tool_summary(self, scan_task_id: int) -> None:
        enabled_names = self._enabled_subdomain_tool_names()
        runs = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == scan_task_id,
                SubdomainToolRun.tool_name.in_(enabled_names),
            )
        ).all()
        if not runs:
            return
        counts: dict[str, int] = {}
        for run in runs:
            counts[run.status] = counts.get(run.status, 0) + 1
        summary = ", ".join(f"{status}={counts[status]}" for status in sorted(counts))
        self._log(f"[subdomain] tool summary: {summary}")
        failed = [run for run in runs if run.status == "failed"]
        if failed:
            sample = "; ".join(
                f"{run.tool_name}:{run.root_domain} {str(run.error_message or '').strip()[:120]}"
                for run in failed[:5]
            )
            self._log(f"[subdomain] failed tool sample: {sample}")

    def _log_dns_coverage_summary(self, scan_task_id: int, root_domains: list[str]) -> None:
        if not root_domains:
            return
        root_set = set(root_domains)
        subdomain_rows = self.session.exec(
            select(SubdomainRecord).where(SubdomainRecord.scan_task_id == scan_task_id)
        ).all()
        dns_rows = self.session.exec(
            select(DnsRecord).where(DnsRecord.scan_task_id == scan_task_id)
        ).all()
        status_rows = self.session.exec(
            select(DnsQueryStatus).where(DnsQueryStatus.scan_task_id == scan_task_id)
        ).all()
        roots_with_subdomains = {row.root_domain for row in subdomain_rows if row.root_domain in root_set}
        roots_with_dns = {row.root_domain for row in dns_rows if row.root_domain in root_set}
        public_ip_roots = {
            row.root_domain
            for row in dns_rows
            if row.root_domain in root_set
            and row.record_type in {"A", "AAAA"}
            and _is_public_ip(row.value)
            and (row.raw_payload or {}).get("kind") != "manual_ip"
        }
        public_ips = {
            row.value
            for row in dns_rows
            if row.record_type in {"A", "AAAA"}
            and _is_public_ip(row.value)
            and (row.raw_payload or {}).get("kind") != "manual_ip"
        }
        manual_ips = {
            row.value
            for row in dns_rows
            if row.record_type in {"A", "AAAA"}
            and _is_public_ip(row.value)
            and (row.raw_payload or {}).get("kind") == "manual_ip"
        }
        failed_queries = [row for row in status_rows if row.status == "failed"]
        self._log(
            "[dns] coverage: "
            f"roots_with_dns={len(roots_with_dns)}/{len(root_domains)}, "
            f"roots_with_subdomains={len(roots_with_subdomains)}/{len(root_domains)}, "
            f"roots_with_public_ip={len(public_ip_roots)}/{len(root_domains)}, "
            f"public_ips={len(public_ips)}, manual_ips={len(manual_ips)}, "
            f"failed_queries={len(failed_queries)}"
        )
        no_subdomains = sorted(root_set - roots_with_subdomains)
        if no_subdomains:
            self._log(f"[dns] roots without discovered subdomains: {', '.join(no_subdomains[:10])}")
        no_public_ip = sorted(root_set - public_ip_roots)
        if no_public_ip:
            self._log(f"[dns] roots without public A/AAAA: {', '.join(no_public_ip[:10])}")

    def _write_subdomain_audit(self, scan_task_id: int, root_domains: list[str] | None = None) -> Path:
        root_domains = root_domains or self._root_domains(scan_task_id)
        root_set = set(root_domains)
        enabled_names = self._enabled_subdomain_tool_names()
        output_dir = Path("data") / "subdomains" / f"task_{scan_task_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        runs = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == scan_task_id,
                SubdomainToolRun.tool_name.in_(enabled_names),
            )
        ).all()
        subdomain_rows = self.session.exec(
            select(SubdomainRecord).where(SubdomainRecord.scan_task_id == scan_task_id)
        ).all()
        dns_rows = self.session.exec(select(DnsRecord).where(DnsRecord.scan_task_id == scan_task_id)).all()
        status_rows = self.session.exec(
            select(DnsQueryStatus).where(DnsQueryStatus.scan_task_id == scan_task_id)
        ).all()

        method_counts: dict[str, int] = {}
        for run in runs:
            key = f"{run.tool_name}:{run.status}"
            method_counts[key] = method_counts.get(key, 0) + 1
        subdomains_by_root: dict[str, int] = {root: 0 for root in root_domains}
        for row in subdomain_rows:
            if row.root_domain in subdomains_by_root:
                subdomains_by_root[row.root_domain] += 1
        dns_record_counts: dict[str, int] = {}
        for row in dns_rows:
            dns_record_counts[row.record_type] = dns_record_counts.get(row.record_type, 0) + 1
        roots_with_dns = {row.root_domain for row in dns_rows if row.root_domain in root_set}
        roots_with_public_ip = {
            row.root_domain
            for row in dns_rows
            if row.root_domain in root_set and row.record_type in {"A", "AAAA"} and _is_public_ip(row.value)
        }
        failed_runs = [
            {
                "tool_name": run.tool_name,
                "root_domain": run.root_domain,
                "exit_code": run.exit_code,
                "interrupted": self._is_interrupted_tool_run(run),
                "error_message": str(run.error_message or run.stderr or run.stdout or "")[:1000],
            }
            for run in runs
            if run.status == "failed"
        ]
        failed_queries = [
            {
                "fqdn": row.fqdn,
                "root_domain": row.root_domain,
                "record_type": row.record_type,
                "error_message": row.error_message,
            }
            for row in status_rows
            if row.status == "failed"
        ]
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "root_domain_count": len(root_domains),
            "root_domains": root_domains,
            "tool_run_counts": dict(sorted(method_counts.items())),
            "failed_tool_runs": failed_runs[:100],
            "interrupted_tool_run_count": sum(1 for item in failed_runs if item["interrupted"]),
            "subdomain_count": len(subdomain_rows),
            "subdomains_by_root": dict(sorted(subdomains_by_root.items())),
            "roots_without_subdomains": sorted(root for root, count in subdomains_by_root.items() if count == 0),
            "dns_record_counts": dict(sorted(dns_record_counts.items())),
            "roots_with_dns_count": len(roots_with_dns),
            "roots_with_public_ip_count": len(roots_with_public_ip),
            "failed_dns_query_count": len(failed_queries),
            "failed_dns_query_samples": failed_queries[:100],
        }
        path = output_dir / "subdomain_audit.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _parse_tool_outputs(self, scan_task_id: int, root_domains: list[str]) -> None:
        runs = self.session.exec(
            select(SubdomainToolRun).where(
                SubdomainToolRun.scan_task_id == scan_task_id,
                SubdomainToolRun.status == "completed",
                SubdomainToolRun.tool_name.in_(SUPPORTED_SUBDOMAIN_TOOLS),
            )
        ).all()
        before = len(self._subdomains(scan_task_id))
        dns_from_tools = 0
        skipped_large_outputs = 0
        max_output_lines = max(1, self.config.tools.subdomain_tool_max_output_lines)
        for run in runs:
            if self._tool_output_exceeds_limit(run, max_output_lines):
                removed = self._delete_tool_only_subdomains(scan_task_id, run.root_domain, run.tool_name)
                skipped_large_outputs += 1
                self._log(
                    f"[subdomain] skipped {run.tool_name} output for {run.root_domain}: "
                    f"more than {max_output_lines} lines, possible wildcard DNS; "
                    f"removed_tool_only={removed}"
                )
                continue
            for line in self._iter_tool_output_lines(run):
                hostname = _tool_line_hostname(line)
                if not hostname:
                    continue
                root = next((domain for domain in root_domains if _is_subdomain(hostname, domain)), None)
                if not root:
                    continue
                self._upsert_subdomain(scan_task_id, root, hostname, run.tool_name)
                dns_from_tools += self._save_tool_dns_values(scan_task_id, root, hostname, line, run.tool_name)
        after = len(self._subdomains(scan_task_id))
        self._log(f"[subdomain] merged unique subdomains: {after} (+{after - before})")
        if dns_from_tools:
            self._log(f"[dns] merged tool DNS records: {dns_from_tools}")
        if skipped_large_outputs:
            self._log(f"[subdomain] skipped large tool outputs: {skipped_large_outputs}")

    def _tool_output_exceeds_limit(self, run: SubdomainToolRun, max_lines: int) -> bool:
        count = 0
        for _line in self._iter_tool_output_lines(run):
            count += 1
            if count > max_lines:
                return True
        return False

    def _iter_tool_output_lines(self, run: SubdomainToolRun) -> Iterable[str]:
        output = Path(run.output_path)
        if output.exists():
            with output.open("r", encoding="utf-8", errors="ignore") as handle:
                yield from handle
        if run.stdout:
            yield from run.stdout.splitlines()

    def _delete_tool_only_subdomains(self, scan_task_id: int, root_domain: str, tool_name: str) -> int:
        result = self.session.exec(
            delete(SubdomainRecord).where(
                SubdomainRecord.scan_task_id == scan_task_id,
                SubdomainRecord.root_domain == root_domain,
                SubdomainRecord.sources == [tool_name],
            )
        )
        self.session.commit()
        return int(result.rowcount or 0)

    def _save_tool_dns_values(
        self,
        scan_task_id: int,
        root_domain: str,
        fqdn: str,
        line: str,
        source: str,
    ) -> int:
        saved = 0
        for record_type, value in _tool_line_dns_values(line):
            if self._upsert_dns_record(
                self.session,
                scan_task_id,
                fqdn,
                root_domain,
                record_type,
                value,
                raw_payload={"source": source, "line": line},
            ):
                saved += 1
        return saved

    def _upsert_subdomain(self, scan_task_id: int, root_domain: str, fqdn: str, source: str) -> None:
        row = self.session.exec(
            select(SubdomainRecord).where(
                SubdomainRecord.scan_task_id == scan_task_id,
                SubdomainRecord.fqdn == fqdn,
            )
        ).first()
        if row:
            if source not in (row.sources or []):
                row.sources = [*list(row.sources or []), source]
            row.last_seen_at = _utcnow()
            self.session.add(row)
            self.session.commit()
            return
        row = SubdomainRecord(
            scan_task_id=scan_task_id,
            root_domain=root_domain,
            fqdn=fqdn,
            sources=[source],
        )
        self.session.add(row)
        self.session.commit()

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = max(1.0, self.config.dns.timeout_seconds)
        resolver.lifetime = min(max(1.0, self.config.dns.lifetime_seconds), 60.0)
        if self.config.dns.nameservers:
            resolver.nameservers = self.config.dns.nameservers
        return resolver

    def _resolve_domains(self, scan_task_id: int, domains: Iterable[str], record_types: Iterable[str]) -> None:
        jobs = []
        for domain in sorted(set(domains)):
            root = self._root_for_domain(scan_task_id, domain)
            for record_type in record_types:
                status = self._dns_status(scan_task_id, domain, record_type)
                if status and status.status == "completed":
                    continue
                jobs.append((domain, root, record_type))
        if not jobs:
            return
        workers = min(max(1, self.config.dns.max_workers), len(jobs), 10)
        self._log(f"[dns] resolving {len(jobs)} queries with workers={workers}")
        saved = 0
        skipped = 0
        completed = 0
        total = len(jobs)
        progress_interval = max(1, total // 10)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._resolve_one, scan_task_id, domain, root, record_type)
                for domain, root, record_type in jobs
            ]
            for future in as_completed(futures):
                result = future.result()
                saved += result.get("saved", 0)
                skipped += result.get("skipped", 0)
                completed += 1
                if completed % progress_interval == 0 or completed == total:
                    self._log(f"[dns] progress: {completed}/{total} queries completed")
        self._log(f"[dns] resolved records saved={saved}, skipped_non_public={skipped}")

    def _root_for_domain(self, scan_task_id: int, fqdn: str) -> str:
        roots = self._root_domains(scan_task_id)
        return next((root for root in roots if fqdn == root or fqdn.endswith(f".{root}")), fqdn)

    def _dns_status(self, scan_task_id: int, fqdn: str, record_type: str) -> DnsQueryStatus | None:
        return self.session.exec(
            select(DnsQueryStatus).where(
                DnsQueryStatus.scan_task_id == scan_task_id,
                DnsQueryStatus.fqdn == fqdn,
                DnsQueryStatus.record_type == record_type,
            )
        ).first()

    def _resolve_one(self, scan_task_id: int, fqdn: str, root_domain: str, record_type: str) -> dict[str, int]:
        saved = 0
        skipped = 0
        with Session(self.session.get_bind()) as session:
            status = session.exec(
                select(DnsQueryStatus).where(
                    DnsQueryStatus.scan_task_id == scan_task_id,
                    DnsQueryStatus.fqdn == fqdn,
                    DnsQueryStatus.record_type == record_type,
                )
            ).first()
            if not status:
                status = DnsQueryStatus(
                    scan_task_id=scan_task_id,
                    fqdn=fqdn,
                    root_domain=root_domain,
                    record_type=record_type,
                )
            try:
                doh_result = self._resolve_doh_records(fqdn, record_type)
                if doh_result["completed"]:
                    for record in doh_result["records"]:
                        value = str(record["value"])
                        if record_type in {"A", "AAAA"} and not _is_public_ip(value):
                            skipped += 1
                            continue
                        if self._upsert_dns_record(
                            session,
                            scan_task_id,
                            fqdn,
                            root_domain,
                            record_type,
                            value,
                            ttl=record.get("ttl"),
                            raw_payload={
                                "source": "doh",
                                "endpoint": record.get("endpoint"),
                                "text": value,
                            },
                        ):
                            saved += 1
                    status.status = "completed"
                    status.error_message = str(doh_result.get("error") or "")[:1000] or None
                    status.queried_at = _utcnow()
                    session.add(status)
                    session.commit()
                    return {"saved": saved, "skipped": skipped}

                resolver = self._resolver()
                answer = resolver.resolve(fqdn, record_type)
                for item in answer:
                    value = self._format_dns_value(record_type, item)
                    if record_type in {"A", "AAAA"} and not _is_public_ip(value):
                        skipped += 1
                        continue
                    if self._upsert_dns_record(
                        session,
                        scan_task_id,
                        fqdn,
                        root_domain,
                        record_type,
                        value,
                        ttl=answer.rrset.ttl if answer.rrset else None,
                        raw_payload={"source": "dns", "text": item.to_text()},
                    ):
                        saved += 1
                status.status = "completed"
                status.error_message = None
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
                status.status = "completed"
                status.error_message = str(exc)[:1000]
            except Exception as exc:
                status.status = "failed"
                status.error_message = str(exc)[:1000]
            status.queried_at = _utcnow()
            session.add(status)
            session.commit()
        return {"saved": saved, "skipped": skipped}

    def _resolve_doh_records(self, fqdn: str, record_type: str) -> dict[str, Any]:
        if record_type not in DOH_RECORD_TYPES:
            return {"completed": False, "records": [], "error": None}
        errors = []
        doh_timeout = min(self.config.dns.lifetime_seconds, 10.0)
        for endpoint in DOH_ENDPOINTS:
            try:
                with httpx.Client(timeout=doh_timeout, trust_env=False) as client:
                    response = client.get(
                        endpoint,
                        params={"name": fqdn, "type": record_type},
                        headers={"Accept": "application/dns-json"},
                    )
                    response.raise_for_status()
                    payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"{endpoint}: {exc}")
                continue

            status = payload.get("Status")
            records = self._doh_answer_records(payload, record_type, endpoint)
            if status == 0:
                error = None if records else f"DoH no {record_type} answer"
                return {"completed": True, "records": records, "error": error}
            if status == 3:
                return {"completed": True, "records": [], "error": "DoH NXDOMAIN"}
            errors.append(f"{endpoint}: DoH status={status}")
        return {"completed": False, "records": [], "error": "; ".join(errors)}

    def _doh_answer_records(self, payload: dict[str, Any], record_type: str, endpoint: str) -> list[dict[str, Any]]:
        expected_type = DOH_RECORD_TYPES[record_type]
        records = []
        for answer in payload.get("Answer") or []:
            if answer.get("type") != expected_type:
                continue
            value = str(answer.get("data") or "").rstrip(".")
            if not value:
                continue
            records.append(
                {
                    "value": value,
                    "ttl": answer.get("TTL"),
                    "endpoint": endpoint,
                }
            )
        return records

    def _format_dns_value(self, record_type: str, item) -> str:
        if record_type in {"A", "AAAA", "CNAME", "NS"}:
            return item.to_text().rstrip(".")
        if record_type == "MX":
            return item.to_text().rstrip(".")
        if record_type == "TXT":
            return " ".join(part.decode("utf-8", errors="replace") for part in item.strings)
        return item.to_text().rstrip(".")

    def _upsert_dns_record(
        self,
        session: Session,
        scan_task_id: int,
        fqdn: str,
        root_domain: str,
        record_type: str,
        value: str,
        *,
        ttl: int | None = None,
        raw_payload: dict | None = None,
    ) -> bool:
        record = DnsRecord(
            scan_task_id=scan_task_id,
            fqdn=fqdn,
            root_domain=root_domain,
            record_type=record_type,
            value=value,
            ttl=ttl,
            raw_payload=raw_payload or {},
        )
        session.add(record)
        try:
            session.commit()
            return True
        except IntegrityError:
            session.rollback()
            return False

    def _run_ai_analysis(self, scan_task_id: int) -> None:
        payloads = self._ai_payloads(scan_task_id)
        if not payloads:
            self._log("[ai] skip: no DNS records")
            return
        fingerprint = stable_hash({"schema_version": 3, "batches": payloads})
        row = self.session.exec(
            select(AiAnalysis).where(
                AiAnalysis.scan_task_id == scan_task_id,
                AiAnalysis.analysis_type == "dns_inference",
            )
        ).first()
        if (
            row
            and row.status == "completed"
            and row.summary
            and row.prompt_json.get("fingerprint") == fingerprint
        ):
            self._log("[ai] skip cached DNS inference")
            return
        responses = []
        summaries = []
        for index, payload in enumerate(payloads, start=1):
            if len(payloads) > 1:
                self._log(f"[ai] DNS inference batch {index}/{len(payloads)} records={len(payload['dns_records'])}")
            response = self._call_ai(self.config.ai, payload)
            responses.append(response)
            summaries.append(response.get("choices", [{}])[0].get("message", {}).get("content") or "")
        summary = summaries[0] if len(summaries) == 1 else self._merge_dns_ai_summaries(summaries)
        if not row:
            row = AiAnalysis(scan_task_id=scan_task_id, analysis_type="dns_inference")
        row.status = "completed"
        row.model = self.config.ai.model
        if len(payloads) == 1:
            row.prompt_json = {"fingerprint": fingerprint, **payloads[0]}
            row.response_json = responses[0]
        else:
            row.prompt_json = {"fingerprint": fingerprint, "schema_version": 3, "batch_count": len(payloads), "batches": payloads}
            row.response_json = {"batches": responses}
        row.summary = summary
        row.updated_at = _utcnow()
        self.session.add(row)
        self.session.commit()
        self._log("[ai] analysis completed")

    def _ai_payload(self, scan_task_id: int) -> dict:
        payloads = self._ai_payloads(scan_task_id)
        return payloads[0] if payloads else {"dns_records": []}

    def _ai_payloads(self, scan_task_id: int) -> list[dict]:
        roots = self._root_domains(scan_task_id)
        records = self.session.exec(
            select(DnsRecord).where(DnsRecord.scan_task_id == scan_task_id)
        ).all()
        if not records:
            return []
        batches = self._dns_record_batches(records)
        payloads = []
        for index, batch_records in enumerate(batches, start=1):
            payloads.append(
                {
                    "schema_version": 3,
                    "scan_task_id": scan_task_id,
                    "batch_index": index,
                    "batch_count": len(batches),
                    "root_domains": roots,
                    "record_format": "fqdn|type|value",
                    "dns_records": self._dns_record_lines(batch_records),
                    "dns_records_truncated": False,
                    "candidate_public_ip_evidence": self._candidate_ip_evidence(batch_records),
                    "instructions": (
                        "Identify likely real public server IPs for nmap scanning in this batch. Exclude IPs that only "
                        "belong to NS infrastructure, obvious CDN/CNAME access, WAF/proxy ranges, or test/"
                        "documentation/private/reserved ranges. You must start with a machine-readable "
                        "NMAP_TARGET_IPS block, then provide concise Chinese analysis."
                    ),
                }
            )
        return payloads

    def _dns_record_lines(self, records: list[DnsRecord]) -> list[str]:
        priority = {"A": 0, "AAAA": 1, "CNAME": 2, "MX": 3, "TXT": 4, "NS": 5, "SOA": 6}
        return sorted(
            {
                self._dns_record_line(record)
                for record in records
            },
            key=lambda line: (
                priority.get(line.split("|", 2)[1], 99),
                line.split("|", 1)[0],
                line,
            ),
        )

    def _dns_record_line(self, record: DnsRecord) -> str:
        return f"{record.fqdn}|{record.record_type}|{record.value}"

    def _dns_record_batches(self, records: list[DnsRecord]) -> list[list[DnsRecord]]:
        ordered = sorted(records, key=lambda record: self._dns_record_lines([record])[0])
        batches: list[list[DnsRecord]] = []
        current: list[DnsRecord] = []
        used_chars = 0
        for record in ordered:
            line = self._dns_record_line(record)
            next_chars = used_chars + len(line) + 1
            if current and (len(current) >= DNS_AI_BATCH_MAX_RECORDS or next_chars > DNS_AI_BATCH_MAX_CHARS):
                batches.append(current)
                current = []
                used_chars = 0
                next_chars = len(line) + 1
            current.append(record)
            used_chars = next_chars
        if current:
            batches.append(current)
        return batches

    def _merge_dns_ai_summaries(self, summaries: list[str]) -> str:
        lines_by_ip: dict[str, str] = {}
        details = []
        for index, summary in enumerate(summaries, start=1):
            for line in self._nmap_target_lines(summary):
                ip = self._first_public_ip(line)
                if ip and ip not in lines_by_ip:
                    lines_by_ip[ip] = line
            details.append(f"批次 {index}:\n{summary}".strip())
        target_lines = list(lines_by_ip.values())
        return "\n".join(
            [
                "NMAP_TARGET_IPS",
                *target_lines,
                "END_NMAP_TARGET_IPS",
                "",
                "分批 DNS AI 分析明细：",
                *details,
            ]
        )

    def _nmap_target_lines(self, summary: str) -> list[str]:
        match = re.search(r"NMAP_TARGET_IPS\s*(.*?)\s*END_NMAP_TARGET_IPS", summary or "", flags=re.I | re.S)
        segment = match.group(1) if match else summary or ""
        lines = []
        for line in segment.splitlines():
            if self._first_public_ip(line):
                lines.append(line.strip())
        return lines

    def _first_public_ip(self, text: str) -> str | None:
        for match in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
            value = match.group(0)
            if _is_public_ip(value):
                return value
        return None

    def _candidate_ip_evidence(self, records: list[DnsRecord]) -> list[dict]:
        cname_by_fqdn: dict[str, list[str]] = {}
        evidence: dict[str, dict] = {}
        for record in records:
            if record.record_type == "CNAME":
                cname_by_fqdn.setdefault(record.fqdn, [])
                if record.value not in cname_by_fqdn[record.fqdn]:
                    cname_by_fqdn[record.fqdn].append(record.value)
        for record in records:
            if record.record_type not in {"A", "AAAA"} or not _is_public_ip(record.value):
                continue
            item = evidence.setdefault(
                record.value,
                {
                    "ip": record.value,
                    "families": set(),
                    "domains": set(),
                    "root_domains": set(),
                    "cname_targets": set(),
                },
            )
            item["families"].add(record.record_type)
            item["domains"].add(record.fqdn)
            item["root_domains"].add(record.root_domain)
            for cname in cname_by_fqdn.get(record.fqdn, []):
                item["cname_targets"].add(cname)
        output = []
        for item in evidence.values():
            output.append(
                {
                    "ip": item["ip"],
                    "families": sorted(item["families"]),
                    "domains": sorted(item["domains"])[:40],
                    "domain_count": len(item["domains"]),
                    "root_domains": sorted(item["root_domains"]),
                    "cname_targets": sorted(item["cname_targets"])[:20],
                }
            )
        return sorted(output, key=lambda item: (-item["domain_count"], item["ip"]))

    def _call_ai(self, config: AiConfig, payload: dict) -> dict:
        messages = [
            {
                "role": "system",
                "content": (
                    "你是互联网资产测绘分析助手。你需要根据 DNS 记录推理真实公网服务 IP，"
                    "排除仅用于 NS 的地址、明显 CNAME/CDN 接入、WAF/代理、保留地址段，并总结有价值线索。"
                    "回答必须以如下机器可读区块开头，供后续 nmap 使用：\n"
                    "NMAP_TARGET_IPS\n"
                    "- <ip> | <high|medium|low> | <简短理由>\n"
                    "END_NMAP_TARGET_IPS\n"
                    "如果没有可信目标，也必须输出空的 NMAP_TARGET_IPS 区块。"
                ),
            },
            {
                "role": "user",
                "content": json.dumps(payload, ensure_ascii=False),
            },
        ]
        return chat_completion(config, messages, temperature=0.1, max_completion_tokens=1600)
