from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import httpx
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.config import AppConfig
from assetmap.models import ServiceAsset, UrlDiscoveryTask, WebEntrypoint, WebProbeResult
from assetmap.services.identification.ai_client import chat_completion, completion_finish_reason


JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.I | re.S)
SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9_.-]+")
LOW_VALUE_TITLE_MARKERS = (
    "404",
    "not found",
    "non-compliance icp filing",
    "forbidden",
    "bad request",
    "nginx",
    "apache tomcat",
    "iis windows server",
)
HTTPS_PORT_HINTS = {443, 8443, 9443, 13380}
PLAIN_HTTP_TO_HTTPS_MARKERS = (
    "plain http request was sent to https port",
    "bad request: the plain http request was sent to https port",
)
BLANK_PAGE_EXTRA_WAIT_MS = 2500
RENDERED_HTML_SETTLE_WAIT_MS = 500
VISUAL_ALLOW_HTTP_STATUSES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403})
BROWSER_WAIT_UNTIL = "domcontentloaded"
BROWSER_HEADLESS = True
RENDERED_HTML_MAX_BYTES = 1_000_000
RENDERED_HTML_PROMPT_CHARS = 32_000
RENDERED_TEXT_PROMPT_CHARS = 16_000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _safe_stem(value: str, max_length: int = 120) -> str:
    return (SAFE_FILENAME.sub("_", value).strip("._") or "entrypoint")[:max_length]


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if value:
        return [str(value)]
    return []


def _wait_until_attempts(primary: str) -> list[str]:
    return _dedupe([primary, "commit", "domcontentloaded", "load"])


def _clean_ai_text(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\ufffd", "").encode("utf-8", errors="ignore").decode("utf-8").strip()
    if isinstance(value, list):
        return [_clean_ai_text(item) for item in value]
    if isinstance(value, dict):
        return {key: _clean_ai_text(item) for key, item in value.items()}
    return value


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class _BrowserRenderedHtmlSession:
    """One reusable Chromium session that captures JavaScript-rendered DOM evidence."""

    def __init__(self, user_agent: str) -> None:
        self.user_agent = user_agent
        self.playwright: Any | None = None
        self.browser: Any | None = None
        self.context: Any | None = None

    def capture(
        self,
        *,
        urls: list[str],
        timeout_seconds: float,
        hard_timeout_seconds: int,
    ) -> tuple[str, dict[str, Any]]:
        self._ensure_started()
        assert self.context is not None
        deadline = time.monotonic() + hard_timeout_seconds
        errors = []
        # httpx 已确认的最终 URL 在第一位；其余仅用于协议或跳转异常时回退。
        for url in urls:
            for wait_until in _wait_until_attempts(BROWSER_WAIT_UNTIL):
                remaining_ms = int((deadline - time.monotonic()) * 1000)
                if remaining_ms <= 0:
                    raise RuntimeError(f"rendered HTML hard timeout after {hard_timeout_seconds}s")
                timeout_ms = min(max(1, int(timeout_seconds * 1000)), remaining_ms)
                page = self.context.new_page()
                page.set_default_timeout(timeout_ms)
                page.set_default_navigation_timeout(timeout_ms)
                try:
                    try:
                        page.goto(url, wait_until=wait_until, timeout=timeout_ms)
                    except Exception as exc:
                        if exc.__class__.__name__ != "TimeoutError" or page.url == "about:blank":
                            raise
                    # Most server-rendered pages are stable immediately after
                    # DOMContentLoaded. Keep a short settle window, and reserve
                    # the longer wait/network-idle retry for actually blank SPAs.
                    page.wait_for_timeout(min(RENDERED_HTML_SETTLE_WAIT_MS, max(1, int((deadline - time.monotonic()) * 1000))))
                    page_state = _page_state(page)
                    if _looks_blank(page_state):
                        try:
                            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 3000))
                        except Exception:
                            pass
                        page.wait_for_timeout(min(BLANK_PAGE_EXTRA_WAIT_MS, max(1, int((deadline - time.monotonic()) * 1000))))
                        page_state = _page_state(page)
                    if _looks_blank(page_state):
                        errors.append(f"{url} [{wait_until}]: blank page after load ({_page_state_summary(page_state)})")
                        continue
                    rendered = _rendered_page_evidence(page)
                    return str(page.url), rendered
                except Exception as exc:
                    errors.append(f"{url} [{wait_until}]: {str(exc)[:400]}")
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
        raise RuntimeError(" | ".join(errors)[-1000:] or "rendered HTML capture failed")

    def close(self) -> None:
        for resource in (self.context, self.browser, self.playwright):
            try:
                if resource:
                    resource.close() if resource is not self.playwright else resource.stop()
            except Exception:
                pass
        self.context = self.browser = self.playwright = None

    def _ensure_started(self) -> None:
        if self.context:
            return
        from playwright.sync_api import sync_playwright

        self.playwright = sync_playwright().start()
        try:
            self.browser = self.playwright.chromium.launch(headless=BROWSER_HEADLESS)
        except Exception:
            self.close()
            raise
        self.context = self.browser.new_context(
            ignore_https_errors=True,
            user_agent=self.user_agent,
            viewport={"width": 1365, "height": 900},
            locale="zh-CN",
        )
        self.context.route(
            "**/*",
            # Images/media/fonts do not contribute to DOM/text identification.
            # Keep scripts, stylesheets and XHR intact so JavaScript applications
            # still render exactly as they would for the extraction workflow.
            lambda route: route.abort()
            if route.request.resource_type in {"font", "image", "media"}
            else route.continue_(),
        )


def _rendered_page_evidence(page: Any) -> dict[str, Any]:
    """Extract the post-JavaScript DOM and the pieces most useful to a text model."""
    return page.evaluate(
        """
        () => {
          const clean = (value, limit) => String(value || '').replace(/\\s+/g, ' ').trim().slice(0, limit);
          const html = document.documentElement ? document.documentElement.outerHTML : '';
          const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(a => ({
            text: clean(a.innerText || a.getAttribute('aria-label'), 160), href: a.href
          })).filter(item => item.text || item.href);
          const forms = Array.from(document.querySelectorAll('input, button, select, textarea')).slice(0, 200).map(el => ({
            tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
            placeholder: el.getAttribute('placeholder') || '', text: clean(el.innerText || el.value || el.getAttribute('aria-label'), 160)
          }));
          return {
            final_url: location.href,
            document_title: document.title || '',
            visible_text: clean(document.body ? document.body.innerText : '', 120000),
            rendered_html: html,
            meta_description: document.querySelector('meta[name="description"]')?.content || '',
            forms, links,
          };
        }
        """
    )


def _page_state(page: Any) -> dict[str, Any]:
    try:
        return page.evaluate(
            """
            () => {
              const body = document.body;
              const viewportHeight = window.innerHeight || 0;
              const viewportWidth = window.innerWidth || 0;
              const text = (body && body.innerText ? body.innerText : '').trim();
              const elements = Array.from(document.querySelectorAll('body *')).slice(0, 1500);
              let visibleElements = 0;
              let mediaElements = 0;
              let formElements = 0;
              for (const el of elements) {
                const rect = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                const visible = rect.width > 2 && rect.height > 2 &&
                  style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
                if (!visible) continue;
                visibleElements += 1;
                const tag = el.tagName.toLowerCase();
                if (['img', 'svg', 'canvas', 'video', 'picture'].includes(tag)) mediaElements += 1;
                if (['input', 'button', 'select', 'textarea'].includes(tag)) formElements += 1;
              }
              return {
                url: location.href,
                title: document.title || '',
                textLength: text.length,
                visibleElements,
                mediaElements,
                formElements,
                bodyHeight: body ? body.scrollHeight : 0,
                bodyWidth: body ? body.scrollWidth : 0,
                viewportHeight,
                viewportWidth
              };
            }
            """
        )
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _looks_blank(state: dict[str, Any]) -> bool:
    if not state or state.get("error"):
        return False
    text_length = int(state.get("textLength") or 0)
    visible_elements = int(state.get("visibleElements") or 0)
    media_elements = int(state.get("mediaElements") or 0)
    form_elements = int(state.get("formElements") or 0)
    body_height = int(state.get("bodyHeight") or 0)
    viewport_height = int(state.get("viewportHeight") or 0)
    title = str(state.get("title") or "").strip()
    has_content_signal = text_length >= 5 or media_elements > 0 or form_elements > 0 or visible_elements >= 3 or title
    return not has_content_signal and body_height <= max(viewport_height + 20, 120)


def _page_state_summary(state: dict[str, Any]) -> str:
    title = repr(state.get("title") or "")
    return (
        f"title={title}, text={state.get('textLength') or 0}, "
        f"visible={state.get('visibleElements') or 0}, media={state.get('mediaElements') or 0}, "
        f"forms={state.get('formElements') or 0}, height={state.get('bodyHeight') or 0}"
    )


class UrlDiscoveryService:
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

    def run(self, scan_task_id: int, rerun: bool = False, retry_failed: bool = False) -> int:
        task = self._task(scan_task_id)
        task.status = "running"
        task.stage = "entrypoints"
        task.error_message = None
        self.session.add(task)
        self.session.commit()
        try:
            self._log("[url] stage=entrypoints: seed URLs from responded web probes")
            if rerun:
                self._log("[url] rerun requested: clearing existing web entrypoints")
                self._clear(scan_task_id)
            if not self._has_service_identification_result(scan_task_id):
                raise ValueError(
                    "No service-identification result exists for this task. "
                    "Run `python -m assetmap.stages.service_identification --task-id "
                    f"{scan_task_id}` before Web identification."
                )
            changed = self._seed_entrypoints(scan_task_id)
            known = self._entrypoint_count(scan_task_id)
            self._log(f"[url] web entrypoints: total={known}, changed_this_run={changed}")
            if self.config.ai.enabled:
                task.stage = "rendered_html_analysis"
                self.session.add(task)
                self.session.commit()
                self._log(
                    "[url] stage=rendered_html_analysis: open each URL with Chromium, "
                    "save JavaScript-rendered HTML, then use AI text analysis"
                )
                self._analyze_rendered_html(scan_task_id, rerun=rerun, retry_failed=retry_failed)
            else:
                self._log("[url] rendered HTML analysis skipped: AI is disabled")
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
            raise
        except Exception as exc:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            self.session.add(task)
            self.session.commit()
            raise

    def _has_service_identification_result(self, scan_task_id: int) -> bool:
        """A missing service row means the prerequisite stage was not run."""
        return (
            self.session.exec(
                select(ServiceAsset.id).where(ServiceAsset.scan_task_id == scan_task_id)
            ).first()
            is not None
        )

    def _task(self, scan_task_id: int) -> UrlDiscoveryTask:
        task = self.session.exec(
            select(UrlDiscoveryTask).where(UrlDiscoveryTask.scan_task_id == scan_task_id)
        ).first()
        if task:
            return task
        task = UrlDiscoveryTask(scan_task_id=scan_task_id)
        self.session.add(task)
        self.session.commit()
        self.session.refresh(task)
        return task

    def _clear(self, scan_task_id: int) -> None:
        for row in self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all():
            self.session.delete(row)
        self.session.commit()

    def _entrypoint_count(self, scan_task_id: int) -> int:
        return len(
            self.session.exec(
                select(WebEntrypoint.id).where(WebEntrypoint.scan_task_id == scan_task_id)
            ).all()
        )

    def _seed_entrypoints(self, scan_task_id: int) -> int:
        probes = self.session.exec(
            select(WebProbeResult).where(
                WebProbeResult.scan_task_id == scan_task_id,
                WebProbeResult.status == "responded",
            )
        ).all()
        self._log(f"[url] responded web probes: {len(probes)}")
        saved = 0
        skipped_status = 0
        skipped_url = 0
        for probe in sorted(probes, key=lambda item: (item.host, item.port, item.url)):
            if probe.http_status not in VISUAL_ALLOW_HTTP_STATUSES:
                skipped_status += 1
                continue
            url_value = self._canonical_probe_url(probe)
            normalized = self._normalize_url(url_value)
            if not normalized:
                skipped_url += 1
                continue
            row = self.session.exec(
                select(WebEntrypoint).where(
                    WebEntrypoint.scan_task_id == scan_task_id,
                    WebEntrypoint.normalized_url == normalized,
                )
            ).first()
            obsolete = self._obsolete_plain_http_entrypoint(scan_task_id, probe, normalized)
            if not row:
                row = WebEntrypoint(
                    scan_task_id=scan_task_id,
                    host=(urlparse(normalized).hostname or probe.host).lower(),
                    url=url_value,
                    normalized_url=normalized,
                    evidence=self._probe_evidence(probe, obsolete),
                )
            else:
                row.evidence = self._merge_probe_evidence(row.evidence or {}, probe, obsolete)
            service = self._service_for_probe(scan_task_id, probe)
            row.service_asset_id = service.id if service else None
            row.target_ip = probe.target_ip
            row.port = probe.port
            row.final_url = url_value if probe.final_url else None
            row.http_status = probe.http_status
            row.title = probe.title
            row.server = probe.server
            row.powered_by = probe.powered_by
            row.content_type = probe.content_type
            row.body_hash = probe.body_hash
            row.body_length = probe.body_length
            row.tech_stack = probe.tech_stack
            self.session.add(row)
            try:
                self.session.commit()
                saved += 1
                if obsolete and obsolete.id != row.id:
                    self.session.delete(obsolete)
                    self.session.commit()
            except IntegrityError:
                self.session.rollback()
        if skipped_status or skipped_url:
            self._log(f"[url] skipped probes: status={skipped_status}, invalid_url={skipped_url}")
        service_saved = self._seed_service_asset_entrypoints(scan_task_id)
        if service_saved:
            self._log(f"[url] service asset fallback entrypoints: {service_saved}")
        canonicalized = self._canonicalize_existing_entrypoints(scan_task_id)
        if canonicalized:
            self._log(f"[url] canonicalized HTTPS-port entrypoints: {canonicalized}")
        return saved + service_saved + canonicalized

    def _canonical_probe_url(self, probe: WebProbeResult) -> str:
        value = probe.final_url or probe.url
        parsed = urlparse(value)
        if parsed.scheme == "http" and self._should_correct_probe_to_https(probe, parsed):
            netloc = (parsed.hostname or probe.host).lower().rstrip(".")
            if parsed.port and parsed.port != 443:
                netloc = f"{netloc}:{parsed.port}"
            return urlunparse(("https", netloc, parsed.path or "/", "", parsed.query, parsed.fragment))
        return value

    def _should_correct_probe_to_https(self, probe: WebProbeResult, parsed) -> bool:
        if not parsed.hostname:
            return False
        title = (probe.title or "").lower()
        port = parsed.port or probe.port
        return port in HTTPS_PORT_HINTS or any(marker in title for marker in PLAIN_HTTP_TO_HTTPS_MARKERS)

    def _obsolete_plain_http_entrypoint(self, scan_task_id: int, probe: WebProbeResult, normalized: str) -> WebEntrypoint | None:
        parsed = urlparse(normalized)
        if parsed.scheme != "https" or (parsed.port or 443) not in HTTPS_PORT_HINTS:
            return None
        netloc = parsed.hostname.lower().rstrip(".") if parsed.hostname else ""
        if parsed.port and parsed.port != 80:
            netloc = f"{netloc}:{parsed.port}"
        old_normalized = urlunparse(("http", netloc, parsed.path or "/", "", parsed.query, ""))
        return self.session.exec(
            select(WebEntrypoint).where(
                WebEntrypoint.scan_task_id == scan_task_id,
                WebEntrypoint.normalized_url == old_normalized,
            )
        ).first()

    def _probe_evidence(self, probe: WebProbeResult, obsolete: WebEntrypoint | None = None) -> dict[str, Any]:
        evidence = {"source": "web_probe", "web_probe_id": probe.id}
        if obsolete:
            evidence["merged_from"] = _dedupe([obsolete.normalized_url, *(_as_list((obsolete.evidence or {}).get("merged_from")))])
        return evidence

    def _merge_probe_evidence(self, evidence: dict[str, Any], probe: WebProbeResult, obsolete: WebEntrypoint | None = None) -> dict[str, Any]:
        merged = dict(evidence)
        merged.setdefault("source", "web_probe")
        merged["web_probe_id"] = probe.id
        if obsolete:
            merged["merged_from"] = _dedupe([*(_as_list(merged.get("merged_from"))), obsolete.normalized_url, *(_as_list((obsolete.evidence or {}).get("merged_from")))])
        return merged

    def _canonicalize_existing_entrypoints(self, scan_task_id: int) -> int:
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        changed = 0
        for row in sorted(rows, key=lambda item: item.normalized_url):
            corrected = self._correct_plain_http_to_https(row.normalized_url, row)
            if not corrected or corrected == row.normalized_url:
                continue
            existing = self.session.exec(
                select(WebEntrypoint).where(
                    WebEntrypoint.scan_task_id == scan_task_id,
                    WebEntrypoint.normalized_url == corrected,
                )
            ).first()
            if existing and existing.id != row.id:
                existing.evidence = self._merge_entrypoint_evidence(existing.evidence or {}, row)
                self.session.add(existing)
                self.session.delete(row)
            else:
                row.evidence = self._merge_entrypoint_evidence(row.evidence or {}, row)
                row.normalized_url = corrected
                row.url = corrected
                if row.final_url:
                    row.final_url = self._correct_plain_http_to_https(row.final_url, row) or row.final_url
                row.host = (urlparse(corrected).hostname or row.host).lower()
                self.session.add(row)
            try:
                self.session.commit()
                changed += 1
            except IntegrityError:
                self.session.rollback()
        return changed

    def _merge_entrypoint_evidence(self, evidence: dict[str, Any], old_row: WebEntrypoint) -> dict[str, Any]:
        merged = dict(evidence)
        merged["merged_from"] = _dedupe([old_row.normalized_url, *(_as_list(merged.get("merged_from"))), *(_as_list((old_row.evidence or {}).get("merged_from")))])
        return merged

    def _seed_service_asset_entrypoints(self, scan_task_id: int) -> int:
        services = self.session.exec(
            select(ServiceAsset).where(
                ServiceAsset.scan_task_id == scan_task_id,
                ServiceAsset.asset_kind == "web",
            )
        ).all()
        saved = 0
        for service in sorted(services, key=lambda item: (item.target_ip, item.port, item.representative_url or "")):
            if not service.representative_url:
                continue
            existing_for_service = self.session.exec(
                select(WebEntrypoint).where(
                    WebEntrypoint.scan_task_id == scan_task_id,
                    WebEntrypoint.service_asset_id == service.id,
                )
            ).first()
            if existing_for_service:
                continue
            normalized = self._normalize_url(service.representative_url)
            if not normalized:
                continue
            row = self.session.exec(
                select(WebEntrypoint).where(
                    WebEntrypoint.scan_task_id == scan_task_id,
                    WebEntrypoint.normalized_url == normalized,
                )
            ).first()
            if row:
                if not row.service_asset_id:
                    row.service_asset_id = service.id
                    self.session.add(row)
                    self.session.commit()
                continue
            row = WebEntrypoint(
                scan_task_id=scan_task_id,
                service_asset_id=service.id,
                target_ip=service.target_ip,
                port=service.port,
                host=(urlparse(normalized).hostname or service.target_ip).lower(),
                url=service.representative_url,
                normalized_url=normalized,
                final_url=service.representative_url,
                http_status=service.http_status,
                title=service.title,
                tech_stack=[],
                evidence={"source": "service_asset", "service_asset_id": service.id},
            )
            self.session.add(row)
            try:
                self.session.commit()
                saved += 1
            except IntegrityError:
                self.session.rollback()
        return saved

    def _normalize_url(self, value: str) -> str | None:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        netloc = parsed.hostname.lower().rstrip(".")
        if port and port != _default_port(parsed.scheme):
            netloc = f"{netloc}:{port}"
        return urlunparse((parsed.scheme.lower(), netloc, (parsed.path or "/").rstrip("/") or "/", "", parsed.query, ""))

    def _service_for_probe(self, scan_task_id: int, probe: WebProbeResult) -> ServiceAsset | None:
        rows = self.session.exec(
            select(ServiceAsset).where(
                ServiceAsset.scan_task_id == scan_task_id,
                ServiceAsset.asset_kind == "web",
                ServiceAsset.port == probe.port,
            )
        ).all()
        for row in rows:
            if row.target_ip == probe.target_ip:
                return row
            if probe.host in (row.domains or []):
                return row
            representative = urlparse(row.representative_url) if row.representative_url else None
            if representative and representative.hostname == probe.host:
                return row
        return None

    def _analyze_rendered_html(self, scan_task_id: int, rerun: bool = False, retry_failed: bool = False) -> None:
        self._clear_stale_visual_errors(scan_task_id)
        migrated = self._invalidate_legacy_visual_analysis(scan_task_id)
        if migrated:
            self._log(f"[url] marked legacy screenshot results for HTML re-analysis: {migrated}")
        reused = self._reuse_duplicate_visual_analysis(scan_task_id)
        if reused:
            self._log(f"[url] reused duplicate visual analysis: {reused}")
        pending_total = len(self._pending_entrypoint_candidates(scan_task_id, rerun, retry_failed=retry_failed))
        entrypoints = self._pending_entrypoints(scan_task_id, rerun, retry_failed=retry_failed)
        if not entrypoints:
            self._log("[url] rendered HTML analysis pending pages: 0")
            self._clear_stale_visual_errors(scan_task_id)
            return
        total_rows = len(self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all())
        remaining_after_batch = max(0, pending_total - len(entrypoints))
        self._log(
            f"[url] rendered HTML analysis pages: {len(entrypoints)} "
            f"(pending_total={pending_total}, remaining_after_batch={remaining_after_batch}, "
            f"total={total_rows}, serial=true, rerun={rerun}, retry_failed={retry_failed})"
        )
        self._require_playwright()
        output_dir = self.config.data_path("rendered_html", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        browser = self._new_rendered_html_session()
        rendered_analysis_cache: dict[str, dict[str, Any]] = {}
        skipped_duplicate_entries = 0
        self._log("[url] Chromium started once and will be reused for this serial HTML batch")
        try:
            for index, entry in enumerate(entrypoints, start=1):
                prefix = f"[url] page {index}/{len(entrypoints)}"
                # A preceding representative may have populated this entry via
                # body-hash reuse during the same run. The original pending list
                # is intentionally retained for deterministic ordering.
                if self._has_saved_analysis(entry):
                    skipped_duplicate_entries += 1
                    self._log(f"{prefix} duplicate content reused; browser and AI skipped -> {entry.normalized_url}")
                    continue
                self._log(f"{prefix} rendered HTML start -> {entry.normalized_url}")
                render_started = time.monotonic()
                try:
                    html_path, final_url, rendered = self._capture_rendered_html(entry, output_dir, browser=browser)
                    self._log(f"{prefix} rendered HTML saved ({time.monotonic() - render_started:.1f}s) -> {html_path}")
                except (RuntimeError, OSError, ValueError) as exc:
                    message = self._error_message(exc)
                    if self._save_probe_fallback(entry.id, message):
                        self._log(f"{prefix} rendered HTML failed, saved probe fallback -> {message[:300]}")
                    else:
                        self._save_error(entry.id, message)
                        self._log(f"{prefix} rendered HTML failed -> {message[:300]}")
                    if "timeout" in message.lower() or "closed" in message.lower():
                        browser.close()
                    continue

                fingerprint = self._rendered_evidence_fingerprint(entry, rendered)
                cached = rendered_analysis_cache.get(fingerprint)
                if cached:
                    reused = {
                        **cached,
                        "analysis_method": "duplicate_reuse",
                        "duplicate_rendered_evidence": fingerprint,
                        "reused_from_method": "rendered_html_ai",
                        "reused_at": _utcnow().isoformat(),
                    }
                    self._save_analysis(entry.id, html_path, final_url, reused)
                    self._log(f"{prefix} same rendered evidence reused; AI skipped")
                    continue

                self._log(f"{prefix} ai analyze start")
                ai_started = time.monotonic()
                try:
                    analysis = self._analyze_rendered_html_with_ai(entry, rendered)
                    self._save_analysis(entry.id, html_path, final_url, analysis)
                    rendered_analysis_cache[fingerprint] = analysis
                    # Reuse the completed representative immediately, instead
                    # of waiting for a second invocation of this stage.
                    reused_by_body_hash = self._reuse_duplicate_visual_analysis(scan_task_id)
                    if reused_by_body_hash:
                        self._log(f"{prefix} body-hash duplicates reused this run: {reused_by_body_hash}")
                    label = analysis.get("system_name") or analysis.get("website_title") or analysis.get("site_purpose") or "ok"
                    self._log(f"{prefix} ai analyze completed ({time.monotonic() - ai_started:.1f}s) -> {label}")
                except httpx.HTTPStatusError as exc:
                    message = self._error_message(exc)
                    if self._save_ai_fallback(entry.id, message, html_path=html_path, final_url=final_url):
                        self._log(f"{prefix} ai analyze failed, saved fallback -> {message[:300]}")
                    else:
                        self._save_error(entry.id, message, html_path=html_path, final_url=final_url)
                        self._log(f"{prefix} ai analyze failed -> {message[:300]}")
                except (httpx.HTTPError, OSError, ValueError) as exc:
                    message = self._error_message(exc)
                    if self._save_ai_fallback(entry.id, message, html_path=html_path, final_url=final_url):
                        self._log(f"{prefix} ai analyze failed, saved fallback -> {message[:300]}")
                    else:
                        self._save_error(entry.id, message, html_path=html_path, final_url=final_url)
                        self._log(f"{prefix} ai analyze failed -> {message[:300]}")
        finally:
            browser.close()
        if skipped_duplicate_entries:
            self._log(f"[url] same-run duplicate entries skipped: {skipped_duplicate_entries}")
        self._clear_stale_visual_errors(scan_task_id)
        self._log_visual_summary(scan_task_id)

    def _require_playwright(self) -> None:
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed; Web identification has not run. "
                "Run `python -m pip install -e \".[visual]\"` and then `playwright install chromium`."
            ) from exc


    def _pending_entrypoints(self, scan_task_id: int, rerun: bool, retry_failed: bool = False) -> list[WebEntrypoint]:
        return self._pending_entrypoint_candidates(scan_task_id, rerun, retry_failed=retry_failed)

    @staticmethod
    def _has_saved_analysis(entry: WebEntrypoint) -> bool:
        return isinstance((entry.evidence or {}).get("visual_analysis"), dict)

    def _pending_entrypoint_candidates(self, scan_task_id: int, rerun: bool, retry_failed: bool = False) -> list[WebEntrypoint]:
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        pending = []
        for row in rows:
            if rerun:
                pending.append(row)
                continue
            evidence = row.evidence or {}
            visual = evidence.get("visual_analysis")
            if visual:
                if (
                    retry_failed
                    and isinstance(visual, dict)
                    and visual.get("analysis_method") == "http_probe_fallback"
                ):
                    pending.append(row)
                    continue
                continue
            if evidence.get("visual_analysis_error"):
                if retry_failed:
                    pending.append(row)
                continue
            pending.append(row)
        return sorted(pending, key=self._entrypoint_sort_key)

    def _entrypoint_sort_key(self, row: WebEntrypoint) -> tuple[int, str]:
        return (-self._entrypoint_score(row), row.normalized_url)

    def _entrypoint_score(self, row: WebEntrypoint) -> int:
        score = 0
        status = row.http_status or 0
        title = (row.title or "").strip().lower()
        parsed = urlparse(row.normalized_url)
        if 200 <= status < 300:
            score += 50
        elif 300 <= status < 400:
            score += 25
        elif status in {401, 403}:
            score += 10
        elif status >= 400:
            score -= 20
        if row.title:
            score += 20
        if title and not any(marker in title for marker in LOW_VALUE_TITLE_MARKERS):
            score += 20
        if parsed.scheme == "https":
            score += 6
        if parsed.hostname and parsed.hostname == (row.target_ip or ""):
            score += 4
        if row.body_length:
            score += min(row.body_length // 1000, 10)
        if row.port in {80, 443}:
            score += 3
        if parsed.scheme == "http" and row.port == 443:
            score -= 30
        if title and any(marker in title for marker in LOW_VALUE_TITLE_MARKERS):
            score -= 25
        return score

    def _log_visual_summary(self, scan_task_id: int) -> None:
        self._normalize_visual_methods(scan_task_id)
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        ok = sum(1 for row in rows if (row.evidence or {}).get("visual_analysis"))
        failed = sum(
            1
            for row in rows
            if (row.evidence or {}).get("visual_analysis_error")
            and not (row.evidence or {}).get("visual_analysis")
        )
        pending = len(rows) - ok - failed
        self._log(f"[url] rendered HTML analysis summary: total={len(rows)}, ok={ok}, failed={failed}, pending={pending}")
        audit = self._write_visual_analysis_audit(scan_task_id, rows)
        self._log(f"[url] rendered HTML analysis audit: {audit}")

    def _normalize_visual_methods(self, scan_task_id: int) -> int:
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        changed = 0
        for row in rows:
            evidence = row.evidence or {}
            visual = evidence.get("visual_analysis")
            if not isinstance(visual, dict) or visual.get("analysis_method"):
                continue
            # Preserve manually imported results. Only explicit legacy methods are
            # migrated below; an unknown method must not be silently relabelled.
            normalized = {**visual, "analysis_method": "manual_or_legacy"}
            row.evidence = {**evidence, "visual_analysis": normalized}
            self.session.add(row)
            changed += 1
        if changed:
            self.session.commit()
        return changed

    def _invalidate_legacy_visual_analysis(self, scan_task_id: int) -> int:
        """Make previous screenshot-based output eligible for the HTML workflow.

        Historical records are retained as lightweight provenance, but cannot
        silently satisfy the replacement HTML-analysis stage. Manually entered
        and unknown integration results are deliberately left untouched.
        """
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        changed = 0
        for row in rows:
            evidence = {**(row.evidence or {})}
            visual = evidence.get("visual_analysis")
            if isinstance(visual, dict):
                method = visual.get("analysis_method")
                is_legacy_duplicate = method == "duplicate_reuse" and not visual.get("reused_from_method")
                is_legacy = method in {"screenshot_ai", "http_probe_fallback"} or is_legacy_duplicate
            else:
                # Older failed runs may only have their screenshot evidence path;
                # move these into the new workflow as well.
                method = "screenshot_error" if evidence.get("visual_analysis_screenshot_path") else ""
                is_legacy = bool(method)
            if not is_legacy:
                continue
            evidence["legacy_visual_analysis"] = {
                "analysis_method": method or "unknown",
                "migrated_at": _utcnow().isoformat(),
            }
            evidence.pop("visual_analysis", None)
            for key in (
                "visual_analysis_error",
                "visual_analysis_error_at",
                "visual_analysis_screenshot_path",
                "visual_analysis_rendered_html_path",
            ):
                evidence.pop(key, None)
            row.evidence = evidence
            self.session.add(row)
            changed += 1
        if changed:
            self.session.commit()
        return changed

    def _write_visual_analysis_audit(self, scan_task_id: int, rows: list[WebEntrypoint] | None = None) -> Path:
        rows = rows or self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        output_dir = self.config.data_path("url_discovery", f"task_{scan_task_id}")
        output_dir.mkdir(parents=True, exist_ok=True)
        method_counts: dict[str, int] = {}
        fallback_samples = []
        failed_samples = []
        low_confidence = []
        low_confidence_count = 0
        html_samples = []
        entries = []
        for row in rows:
            evidence = row.evidence or {}
            visual = evidence.get("visual_analysis") or {}
            method = visual.get("analysis_method") if isinstance(visual, dict) else ""
            if visual and not method:
                method = "manual_or_legacy"
            if not visual and evidence.get("visual_analysis_error"):
                method = "failed"
            if not method:
                method = "pending"
            method_counts[method] = method_counts.get(method, 0) + 1
            item = {
                "entry_id": row.id,
                "url": row.normalized_url,
                "final_url": row.final_url or "",
                "host": row.host,
                "target_ip": row.target_ip or "",
                "port": row.port or "",
                "http_status": row.http_status,
                "title": row.title or "",
                "method": method,
                "system_name": visual.get("system_name") if isinstance(visual, dict) else "",
                "site_purpose": visual.get("site_purpose") if isinstance(visual, dict) else "",
                "confidence": visual.get("confidence") if isinstance(visual, dict) else "",
                "rendered_html_path": visual.get("rendered_html_path") if isinstance(visual, dict) else "",
                "error": evidence.get("visual_analysis_error") or "",
            }
            entries.append(item)
            if method == "http_probe_fallback" and len(fallback_samples) < 50:
                fallback_samples.append(
                    {
                        **item,
                        "rendered_html_error": visual.get("rendered_html_error") if isinstance(visual, dict) else "",
                        "ai_error": visual.get("ai_error") if isinstance(visual, dict) else "",
                    }
                )
            if method == "failed" and len(failed_samples) < 50:
                failed_samples.append({**item, "error": evidence.get("visual_analysis_error")})
            confidence = _float_or_none(visual.get("confidence")) if isinstance(visual, dict) else None
            if confidence is not None and confidence < 0.5:
                low_confidence_count += 1
                if len(low_confidence) < 50:
                    low_confidence.append({**item, "confidence": confidence})
            html_path = visual.get("rendered_html_path") if isinstance(visual, dict) else ""
            if html_path and len(html_samples) < 50:
                html_samples.append({**item, "rendered_html_path": html_path})
        payload = {
            "scan_task_id": scan_task_id,
            "generated_at": _utcnow().isoformat(),
            "total": len(rows),
            "method_counts": dict(sorted(method_counts.items())),
            "fallback_count": method_counts.get("http_probe_fallback", 0),
            "failed_count": method_counts.get("failed", 0),
            "pending_count": method_counts.get("pending", 0),
            "rendered_html_count": sum(1 for item in entries if item.get("rendered_html_path")),
            "low_confidence_count": low_confidence_count,
            "entries": entries,
            "fallback_samples": fallback_samples,
            "failed_samples": failed_samples,
            "low_confidence_samples": low_confidence,
            "rendered_html_samples": html_samples,
        }
        path = output_dir / "visual_analysis_audit.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _new_rendered_html_session(self) -> _BrowserRenderedHtmlSession:
        return _BrowserRenderedHtmlSession(self.config.web_probe.user_agent)

    def _capture_rendered_html(
        self,
        entry: WebEntrypoint,
        output_dir: Path,
        *,
        browser: _BrowserRenderedHtmlSession | None = None,
    ) -> tuple[Path, str, dict[str, Any]]:
        cfg = self.config.url_discovery
        path = output_dir / f"{entry.id or _safe_stem(entry.normalized_url)}_{_safe_stem(entry.host)}.html"
        urls = self._rendered_html_candidate_urls(entry)
        owned_browser = browser is None
        browser = browser or self._new_rendered_html_session()
        try:
            final_url, rendered = browser.capture(
                urls=urls,
                timeout_seconds=cfg.timeout_seconds,
                hard_timeout_seconds=cfg.page_hard_timeout_seconds,
            )
            html = str(rendered.get("rendered_html") or "")
            path.write_text(html[:RENDERED_HTML_MAX_BYTES], encoding="utf-8")
            rendered = {**rendered, "rendered_html": html[:RENDERED_HTML_PROMPT_CHARS]}
            return path, final_url, rendered
        finally:
            if owned_browser:
                browser.close()

    def _rendered_html_candidate_urls(self, entry: WebEntrypoint) -> list[str]:
        primary = entry.final_url or entry.url or entry.normalized_url
        candidates = []
        corrected = self._correct_plain_http_to_https(primary, entry)
        if corrected:
            candidates.append(corrected)
        for value in (primary, entry.normalized_url, entry.url, entry.final_url):
            if value:
                candidates.append(value)
        return _dedupe([value for value in candidates if self._normalize_url(value)])

    def _correct_plain_http_to_https(self, value: str, entry: WebEntrypoint) -> str | None:
        parsed = urlparse(value)
        if parsed.scheme != "http" or not parsed.hostname:
            return None
        title = (entry.title or "").lower()
        port = parsed.port or entry.port
        has_https_hint = port in HTTPS_PORT_HINTS or any(marker in title for marker in PLAIN_HTTP_TO_HTTPS_MARKERS)
        if not has_https_hint:
            return None
        netloc = parsed.hostname.lower().rstrip(".")
        if parsed.port and parsed.port != 443:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse(("https", netloc, parsed.path or "/", "", parsed.query, parsed.fragment))

    def _analyze_rendered_html_with_ai(self, entry: WebEntrypoint, rendered: dict[str, Any]) -> dict[str, Any]:
        messages = self._rendered_html_messages(entry, rendered)
        response = chat_completion(
            self.config.ai,
            messages,
            temperature=0.1,
            max_completion_tokens=1200,
            timeout_seconds=self.config.url_discovery.ai_timeout_seconds,
        )
        content = response.get("choices", [{}])[0].get("message", {}).get("content") or ""
        analysis, parsed = self._parse_json_with_status(content)
        if completion_finish_reason(response).lower() == "length" or not parsed:
            retry_response = chat_completion(
                self.config.ai,
                self._compact_rendered_html_messages(entry, rendered),
                temperature=0.0,
                max_completion_tokens=1600,
                timeout_seconds=self.config.url_discovery.ai_timeout_seconds,
            )
            retry_content = retry_response.get("choices", [{}])[0].get("message", {}).get("content") or ""
            retry_analysis, retry_parsed = self._parse_json_with_status(retry_content)
            if retry_parsed:
                analysis = retry_analysis
                analysis["retry_reason"] = "finish_reason=length" if completion_finish_reason(response).lower() == "length" else "invalid_json"
        analysis["model"] = self.config.ai.model
        return analysis

    def _rendered_html_messages(self, entry: WebEntrypoint, rendered: dict[str, Any]) -> list[dict[str, str]]:
        payload = self._rendered_html_payload(entry, rendered, compact=False)
        return [
            {
                "role": "system",
                "content": (
                    "你是互联网资产测绘分析助手。根据浏览器加载 JavaScript 后提取的 HTML、"
                    "可见文本和页面结构识别系统名称、网站用途、页面类型、所属组织、登录特征、"
                    "业务功能和可见技术线索。不要臆测页面中不存在的信息；只输出严格 JSON。"
                ),
            },
            {
                "role": "user",
                "content": json.dumps(_clean_ai_text(payload), ensure_ascii=False),
            },
        ]

    def _compact_rendered_html_messages(self, entry: WebEntrypoint, rendered: dict[str, Any]) -> list[dict[str, str]]:
        return [
            {
                "role": "system",
                "content": (
                    "只输出一个紧凑 JSON 对象，不要 Markdown，不要解释。字段："
                    "system_name, website_title, site_purpose, page_type, organization, "
                    "login_features, business_functions, tech_stack, confidence, notes。"
                ),
            },
            {
                "role": "user",
                "content": json.dumps(_clean_ai_text(self._rendered_html_payload(entry, rendered, compact=True)), ensure_ascii=False),
            },
        ]

    def _rendered_html_payload(self, entry: WebEntrypoint, rendered: dict[str, Any], *, compact: bool) -> dict[str, Any]:
        html_limit = 8_000 if compact else RENDERED_HTML_PROMPT_CHARS
        text_limit = 4_000 if compact else RENDERED_TEXT_PROMPT_CHARS
        return {
            "url": rendered.get("final_url") or entry.final_url or entry.url,
            "httpx_title": entry.title,
            "document_title": rendered.get("document_title") or "",
            "meta_description": rendered.get("meta_description") or "",
            "http_status": entry.http_status,
            "server": entry.server,
            "known_tech_stack": entry.tech_stack,
            "visible_text": str(rendered.get("visible_text") or "")[:text_limit],
            "forms": (rendered.get("forms") or [])[:80],
            "links": (rendered.get("links") or [])[:80],
            "rendered_html": str(rendered.get("rendered_html") or "")[:html_limit],
        }

    def _rendered_evidence_fingerprint(self, entry: WebEntrypoint, rendered: dict[str, Any]) -> str:
        """Fingerprint the exact text evidence that would be sent to the AI.

        The final URL is included by `_rendered_html_payload`, so entries which
        merely look similar but resolve to different systems are not reused.
        """
        payload = _clean_ai_text(self._rendered_html_payload(entry, rendered, compact=False))
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _parse_json(self, content: str) -> dict[str, Any]:
        data, _parsed = self._parse_json_with_status(content)
        return data

    def _parse_json_with_status(self, content: str) -> tuple[dict[str, Any], bool]:
        text = content.strip()
        match = JSON_BLOCK.search(text)
        if match:
            text = match.group(1).strip()
        if not text.startswith("{"):
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                text = text[start : end + 1]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"notes": content[:2000], "confidence": 0}, False
        return (data, True) if isinstance(data, dict) else ({"notes": content[:2000], "confidence": 0}, False)

    def _error_message(self, exc: BaseException) -> str:
        if isinstance(exc, httpx.HTTPStatusError):
            detail = exc.response.text[:500].strip()
            reason = exc.response.reason_phrase or "HTTP error"
            return f"AI HTTP {exc.response.status_code} {reason}: {detail or str(exc)}"
        return str(exc)[:1000]

    def _save_analysis(self, entry_id: int | None, html_path: Path, final_url: str, analysis: dict[str, Any]) -> None:
        if entry_id is None:
            return
        entry = self.session.get(WebEntrypoint, entry_id)
        if not entry:
            return
        entry.final_url = final_url
        evidence = {**(entry.evidence or {})}
        for key in (
            "visual_analysis_error",
            "visual_analysis_error_at",
            "visual_analysis_screenshot_path",
            "visual_analysis_rendered_html_path",
        ):
            evidence.pop(key, None)
        evidence["visual_analysis"] = {
            **analysis,
            "analysis_method": analysis.get("analysis_method") or "rendered_html_ai",
            "rendered_html_path": str(html_path),
            "analyzed_at": _utcnow().isoformat(),
        }
        entry.evidence = evidence
        if analysis.get("website_title") and not entry.title:
            entry.title = str(analysis["website_title"])[:300]
        self.session.add(entry)
        self._sync_service_visual_evidence(entry, evidence["visual_analysis"])
        self.session.commit()

    def _save_error(
        self,
        entry_id: int | None,
        message: str,
        *,
        html_path: Path | None = None,
        final_url: str | None = None,
    ) -> None:
        if entry_id is None:
            return
        entry = self.session.get(WebEntrypoint, entry_id)
        if not entry:
            return
        if final_url:
            entry.final_url = final_url
        evidence = {
            **(entry.evidence or {}),
            "visual_analysis_error": message[:1000],
            "visual_analysis_error_at": _utcnow().isoformat(),
        }
        if html_path:
            evidence["visual_analysis_rendered_html_path"] = str(html_path)
        entry.evidence = evidence
        self.session.add(entry)
        self.session.commit()

    def _save_probe_fallback(self, entry_id: int | None, message: str) -> bool:
        if entry_id is None:
            return False
        entry = self.session.get(WebEntrypoint, entry_id)
        if not entry or not self._has_probe_evidence(entry):
            return False
        title = _clean_ai_text(self._fallback_title(entry))
        analysis = {
            "system_name": title or "",
            "website_title": title or "",
            "site_purpose": "页面渲染 HTML 获取失败，依据 HTTP 探测信息保留的降级识别结果。",
            "page_type": "http_probe_fallback",
            "visible_technical_clues": _clean_ai_text(entry.tech_stack or []),
            "confidence": 0.35,
            "analysis_method": "http_probe_fallback",
            "rendered_html_error": message[:1000],
        }
        evidence = {**(entry.evidence or {})}
        for key in (
            "visual_analysis_error",
            "visual_analysis_error_at",
            "visual_analysis_screenshot_path",
            "visual_analysis_rendered_html_path",
        ):
            evidence.pop(key, None)
        evidence["visual_analysis"] = {
            **analysis,
            "analyzed_at": _utcnow().isoformat(),
        }
        entry.evidence = evidence
        self.session.add(entry)
        self._sync_service_visual_evidence(entry, evidence["visual_analysis"])
        self.session.commit()
        return True

    def _fallback_title(self, entry: WebEntrypoint) -> str:
        if entry.title:
            return entry.title
        if entry.service_asset_id:
            service = self.session.get(ServiceAsset, entry.service_asset_id)
            if service:
                for value in (service.title, service.app_name, service.product, service.service):
                    if value:
                        return str(value)
        return entry.host or entry.normalized_url or ""

    def _save_ai_fallback(
        self,
        entry_id: int | None,
        message: str,
        *,
        html_path: Path,
        final_url: str,
    ) -> bool:
        if entry_id is None:
            return False
        entry = self.session.get(WebEntrypoint, entry_id)
        if not entry or not self._has_probe_evidence(entry):
            return False
        entry.final_url = final_url
        title = _clean_ai_text(self._fallback_title(entry))
        analysis = {
            "system_name": title or "",
            "website_title": title or "",
            "site_purpose": "渲染后的 HTML 已保存，但 AI 文本分析失败；依据 HTTP 探测信息保留的降级识别结果。",
            "page_type": "ai_analysis_fallback",
            "visible_technical_clues": _clean_ai_text(entry.tech_stack or []),
            "confidence": 0.4,
            "analysis_method": "http_probe_fallback",
            "rendered_html_path": str(html_path),
            "ai_error": message[:1000],
        }
        evidence = {**(entry.evidence or {})}
        for key in (
            "visual_analysis_error",
            "visual_analysis_error_at",
            "visual_analysis_screenshot_path",
            "visual_analysis_rendered_html_path",
        ):
            evidence.pop(key, None)
        evidence["visual_analysis"] = {
            **analysis,
            "analyzed_at": _utcnow().isoformat(),
        }
        entry.evidence = evidence
        self.session.add(entry)
        self._sync_service_visual_evidence(entry, evidence["visual_analysis"])
        self.session.commit()
        return True

    def _sync_service_visual_evidence(self, entry: WebEntrypoint, visual: dict[str, Any]) -> None:
        if not entry.service_asset_id or not isinstance(visual, dict):
            return
        service = self.session.get(ServiceAsset, entry.service_asset_id)
        if not service:
            return
        record = self._service_visual_record(entry, visual)
        evidence = {**(service.evidence or {})}
        records = [
            item
            for item in evidence.get("visual_entrypoints", [])
            if isinstance(item, dict) and item.get("url") != record["url"]
        ]
        records.append(record)
        records = sorted(records, key=lambda item: item.get("url") or "")
        evidence["visual_entrypoints"] = records
        evidence["visual_analysis_count"] = len(records)
        evidence["rendered_html_count"] = sum(1 for item in records if item.get("rendered_html_path"))
        evidence.pop("visual_screenshot_count", None)
        evidence["visual_analysis"] = self._representative_service_visual(records)
        service.evidence = evidence
        title = record.get("website_title") or record.get("system_name")
        if title and not service.title:
            service.title = str(title)[:300]
        if record.get("system_name") and not service.app_name:
            service.app_name = str(record["system_name"])[:300]
        self.session.add(service)

    def _service_visual_record(self, entry: WebEntrypoint, visual: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": entry.normalized_url,
            "final_url": entry.final_url or visual.get("final_url") or "",
            "host": entry.host,
            "target_ip": entry.target_ip or "",
            "port": entry.port or "",
            "http_status": entry.http_status or "",
            "html_title": entry.title or "",
            "system_name": visual.get("system_name") or visual.get("website_title") or "",
            "website_title": visual.get("website_title") or "",
            "site_purpose": visual.get("site_purpose") or "",
            "page_type": visual.get("page_type") or "",
            "analysis_method": visual.get("analysis_method") or "rendered_html_ai",
            "confidence": visual.get("confidence") if visual.get("confidence") is not None else "",
            "rendered_html_path": visual.get("rendered_html_path") or "",
            "analyzed_at": visual.get("analyzed_at") or _utcnow().isoformat(),
        }

    def _representative_service_visual(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        def score(item: dict[str, Any]) -> tuple[float, int, int, str]:
            confidence = _float_or_none(item.get("confidence")) or 0.0
            has_label = 1 if item.get("system_name") or item.get("site_purpose") else 0
            has_rendered_html = 1 if item.get("rendered_html_path") else 0
            return (confidence, has_label, has_rendered_html, item.get("url") or "")

        return dict(max(records, key=score)) if records else {}

    def _has_probe_evidence(self, entry: WebEntrypoint) -> bool:
        status = entry.http_status or 0
        if (entry.evidence or {}).get("source") == "service_asset":
            return True
        if status <= 0:
            return False
        if entry.title or entry.server or entry.powered_by or entry.tech_stack:
            return True
        return 200 <= status < 400 and bool(entry.body_hash)

    def _reuse_duplicate_visual_analysis(self, scan_task_id: int) -> int:
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        by_hash: dict[str, dict[str, Any]] = {}
        for row in sorted(rows, key=self._entrypoint_sort_key):
            evidence = row.evidence or {}
            visual = evidence.get("visual_analysis")
            if row.body_hash and visual and visual.get("analysis_method") == "rendered_html_ai":
                by_hash.setdefault(row.body_hash, visual)
        changed = 0
        for row in rows:
            if not row.body_hash or row.body_hash not in by_hash:
                continue
            evidence = {**(row.evidence or {})}
            if evidence.get("visual_analysis"):
                continue
            reused = {
                **by_hash[row.body_hash],
                "analysis_method": "duplicate_reuse",
                "reused_from_method": "rendered_html_ai",
                "duplicate_body_hash": row.body_hash,
                "reused_at": _utcnow().isoformat(),
            }
            for key in (
                "visual_analysis_error",
                "visual_analysis_error_at",
                "visual_analysis_screenshot_path",
                "visual_analysis_rendered_html_path",
            ):
                evidence.pop(key, None)
            evidence["visual_analysis"] = reused
            row.evidence = evidence
            self.session.add(row)
            self._sync_service_visual_evidence(row, reused)
            changed += 1
        if changed:
            self.session.commit()
        return changed

    def _clear_stale_visual_errors(self, scan_task_id: int) -> None:
        changed = 0
        rows = self.session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == scan_task_id)).all()
        for row in rows:
            evidence = row.evidence or {}
            if not evidence.get("visual_analysis") or not evidence.get("visual_analysis_error"):
                continue
            cleaned = {**evidence}
            for key in (
                "visual_analysis_error",
                "visual_analysis_error_at",
                "visual_analysis_screenshot_path",
                "visual_analysis_rendered_html_path",
            ):
                cleaned.pop(key, None)
            row.evidence = cleaned
            self.session.add(row)
            changed += 1
        if changed:
            self.session.commit()
            self._log(f"[url] cleared stale visual errors: {changed}")
