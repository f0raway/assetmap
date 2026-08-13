from __future__ import annotations

import json
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from ruamel.yaml import YAML
from sqlmodel import select

from assetmap.cli.pipeline import _run_one_click_scan, _run_pipeline
from assetmap.config import AppConfig, DEFAULT_CONFIG_PATH, load_config, write_sample_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import ScanTask
from assetmap.services.delivery.report import _safe_name
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.runtime.environment import EnvironmentCheckService
from assetmap.services.runtime.tool_install import ToolInstallService


SECRET_PATHS = {
    "enterprise_discovery.tycid",
    "enterprise_discovery.auth_token",
    "fofa.api_key",
    "ai.api_key",
}
FIELD_LABELS = {
    "database": "本地数据库",
    "database.url": "数据库地址",
    "enterprise_discovery": "企业发现",
    "enterprise_discovery.tycid": "天眼查 ID",
    "enterprise_discovery.auth_token": "天眼查授权 Token",
    "enterprise_discovery.control_threshold": "控股纳入阈值",
    "enterprise_discovery.max_depth": "最大股权层级",
    "domain_mapping": "域名测绘",
    "domain_mapping.subfinder_provider_config": "Subfinder Provider 配置文件",
    "domain_mapping.dnsx_wordlist": "Dnsx 子域名字典",
    "tools": "外部工具与主动测绘",
    "tools.nmap_command": "Nmap 主扫描命令",
    "fofa": "FOFA",
    "fofa.email": "FOFA 邮箱",
    "fofa.api_key": "FOFA API Key",
    "ai": "AI 网关",
    "ai.enabled": "启用 AI 分析",
    "ai.base_url": "网关地址",
    "ai.api_key": "API Key",
    "ai.api_key_header": "密钥请求头",
    "ai.model": "模型名称",
    "ai.timeout_seconds": "AI 超时（秒）",
    "ai.max_dns_records": "DNS 最大输入记录",
    "ai.max_prompt_chars": "提示词最大字符数",
    "ai.max_completion_tokens": "最大输出 Token",
    "web_probe": "Web 服务探测",
    "web_probe.timeout_seconds": "探测超时（秒）",
    "web_probe.user_agent": "User-Agent",
    "url_discovery": "Web 渲染 HTML 与智能识别",
    "url_discovery.timeout_seconds": "页面打开超时（秒）",
    "url_discovery.page_hard_timeout_seconds": "页面硬超时（秒）",
    "url_discovery.ai_timeout_seconds": "HTML AI 超时（秒）",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _label(path: str) -> str:
    return FIELD_LABELS.get(path, path.rsplit(".", 1)[-1].replace("_", " "))


def _mask_config(value: Any, path: str = "") -> Any:
    if path in SECRET_PATHS:
        return ""
    if isinstance(value, dict):
        return {key: _mask_config(item, f"{path}.{key}" if path else key) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_config(item, path) for item in value]
    return value


def _field_tree(value: Any, path: str = "") -> list[dict[str, Any]]:
    fields = []
    for key, item in value.items():
        field_path = f"{path}.{key}" if path else key
        if isinstance(item, dict):
            fields.append({"type": "group", "path": field_path, "label": _label(field_path), "children": _field_tree(item, field_path)})
            continue
        kind = "secret" if field_path in SECRET_PATHS else "list" if isinstance(item, list) else "boolean" if isinstance(item, bool) else "number" if isinstance(item, (int, float)) else "text"
        fields.append({"type": "field", "path": field_path, "label": _label(field_path), "kind": kind, "value": "" if kind == "secret" else item, "saved": field_path in SECRET_PATHS})
    return fields


def _merge_config(current: Any, submitted: Any, path: str = "") -> Any:
    if not isinstance(current, dict) or not isinstance(submitted, dict):
        if path in SECRET_PATHS and submitted in {None, ""}:
            return current
        return submitted
    result = dict(current)
    for key, value in submitted.items():
        child_path = f"{path}.{key}" if path else key
        if key in current:
            result[key] = _merge_config(current[key], value, child_path)
    return result


def save_config(path: Path, config: AppConfig) -> None:
    """Round-trip YAML so the annotated template remains readable after UI edits."""
    yaml = YAML()
    yaml.preserve_quotes = True
    original: Any = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as stream:
            original = yaml.load(stream) or {}
    if not isinstance(original, dict):
        original = {}
    # Older configuration files used these two sections for enterprise discovery.
    # Remove them only while writing an already validated new configuration.
    original.pop("org", None)
    original.pop("enscan", None)
    original.pop("dns", None)
    tools = original.get("tools")
    if isinstance(tools, dict):
        for key in (
            "subdomain_tools_enabled", "subdomain_tool_timeout_seconds", "subdomain_tool_max_output_lines",
            "subfinder_command", "dnsx_command", "wordlist", "tools_dir",
        ):
            tools.pop(key, None)
    original.pop("port_scan", None)
    if isinstance(tools, dict):
        for key in ("nmap_service_detect_command", "nmap_max_workers", "nmap_timeout_seconds"):
            tools.pop(key, None)
    fofa = original.get("fofa")
    if isinstance(fofa, dict):
        for key in ("base_url", "fields", "size", "full", "timeout_seconds"):
            fofa.pop(key, None)
    web_probe = original.get("web_probe")
    if isinstance(web_probe, dict):
        for key in ("max_workers", "max_domains_per_ip"):
            web_probe.pop(key, None)
    _update_yaml_document(original, config.model_dump(mode="json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        yaml.dump(original, stream)


def _update_yaml_document(document: dict[str, Any], values: dict[str, Any]) -> None:
    for key, value in values.items():
        existing = document.get(key)
        if isinstance(value, dict) and isinstance(existing, dict):
            _update_yaml_document(existing, value)
        else:
            document[key] = value


@dataclass
class UiJob:
    id: str
    kind: str
    label: str
    status: str = "running"
    task_id: int | None = None
    started_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None
    error: str | None = None
    lines: list[str] = field(default_factory=list)


class LocalJobRunner:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self._lock = threading.Lock()
        self._jobs: dict[str, UiJob] = {}

    def start(self, kind: str, label: str, work: Callable[[Callable[[str], None]], int | None]) -> UiJob:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("已有任务正在运行，请等待其完成后再启动下一项操作。")
        job = UiJob(id=uuid.uuid4().hex[:12], kind=kind, label=label)
        self._jobs[job.id] = job

        def progress(message: str) -> None:
            job.lines.append(str(message))
            if len(job.lines) > 1200:
                del job.lines[:200]

        def run() -> None:
            try:
                job.task_id = work(progress)
                job.status = "completed"
            except BaseException as exc:  # Keep CLI exits and background errors visible in the UI.
                job.status = "failed"
                job.error = str(exc) or exc.__class__.__name__
                progress(f"[ui] task failed: {job.error}")
                if not isinstance(exc, SystemExit):
                    traceback.print_exc()
            finally:
                job.finished_at = _utcnow()
                self._lock.release()

        threading.Thread(target=run, daemon=True, name=f"assetmap-ui-{kind}").start()
        return job

    def get(self, job_id: str) -> UiJob | None:
        return self._jobs.get(job_id)

    def list(self) -> list[UiJob]:
        return sorted(self._jobs.values(), key=lambda job: job.started_at, reverse=True)[:20]


def _task_rows(config: AppConfig) -> list[dict[str, Any]]:
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        tasks = session.exec(select(ScanTask).order_by(ScanTask.id.desc())).all()
        status_service = PipelineStatusService(session)
        rows = []
        for task in tasks[:40]:
            pipeline = status_service.get(task.id)
            rows.append({
                "id": task.id,
                "target": task.target,
                "status": task.status,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "next_step": pipeline.next_step.replace("<task_id>", str(task.id)) if pipeline.next_step else None,
                "stages": [{"name": name, "status": state} for name, state, _ in pipeline.stages],
            })
        return rows
    finally:
        session.close()


def create_app(config_path: Path | str = DEFAULT_CONFIG_PATH) -> FastAPI:
    path = Path(config_path)
    if not path.exists():
        write_sample_config(path, overwrite=False)
    runner = LocalJobRunner(path)
    app = FastAPI(title="assetmap 本机控制台", docs_url=None, redoc_url=None)
    static_dir = Path(__file__).with_name("static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return (static_dir / "index.html").read_text(encoding="utf-8")

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        config = load_config(path)
        environment = EnvironmentCheckService(config).check()
        return {
            "environment": environment,
            "ready": all(item["ok"] for item in environment),
            "tasks": _task_rows(config),
            "config_path": str(path),
            "local_only": True,
        }

    @app.get("/api/config")
    def get_config() -> dict[str, Any]:
        config = load_config(path)
        raw = config.model_dump(mode="json")
        return {"fields": _field_tree(_mask_config(raw)), "config_path": str(path)}

    @app.put("/api/config")
    async def update_config(request: Request) -> dict[str, Any]:
        submitted = await request.json()
        if not isinstance(submitted, dict):
            raise HTTPException(400, "配置内容必须是对象。")
        current = load_config(path).model_dump(mode="json")
        try:
            config = AppConfig.model_validate(_merge_config(current, submitted))
        except Exception as exc:
            raise HTTPException(422, f"配置校验失败：{exc}") from exc
        save_config(path, config)
        return {"ok": True, "message": "配置已保存。密钥字段保持脱敏，留空不会覆盖已保存的值。"}

    @app.post("/api/scans")
    async def start_scan(request: Request) -> dict[str, Any]:
        payload = await request.json()
        target = str(payload.get("target") or "").strip()
        if not target:
            raise HTTPException(422, "请填写目标公司名称。")
        refresh = bool(payload.get("refresh"))
        no_ai = bool(payload.get("no_ai"))
        strict = bool(payload.get("strict"))

        def work(progress: Callable[[str], None]) -> int:
            config = load_config(path)
            engine = create_db_and_engine(config.database_url)
            session = get_session(engine)
            try:
                return _run_one_click_scan(
                    session,
                    config,
                    target,
                    refresh=refresh,
                    no_manual_prompt=True,
                    no_ai=no_ai,
                    strict=strict,
                    progress=progress,
                )
            finally:
                session.close()

        try:
            job = runner.start("scan", f"测绘：{target}", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job": _job_data(job)}

    @app.post("/api/tasks/{task_id}/resume")
    async def resume_task(task_id: int, request: Request) -> dict[str, Any]:
        payload = await request.json()
        from_stage = str(payload.get("from_stage") or "subdomains")
        rerun = bool(payload.get("rerun"))

        def work(progress: Callable[[str], None]) -> int:
            config = load_config(path)
            engine = create_db_and_engine(config.database_url)
            session = get_session(engine)
            try:
                _run_pipeline(
                    session,
                    config,
                    task_id,
                    progress=progress,
                    from_stage=from_stage,
                    rerun=rerun,
                    rerun_subdomain_tools=bool(payload.get("rerun_subdomain_tools")),
                    rerun_dns=bool(payload.get("rerun_dns")),
                    rerun_ports=bool(payload.get("rerun_ports")),
                    rerun_classify=bool(payload.get("rerun_classify")),
                    rerun_urls=bool(payload.get("rerun_urls")),
                    rerun_ai=bool(payload.get("rerun_ai")),
                    no_ai=bool(payload.get("no_ai")),
                    retry_failed_url=bool(payload.get("retry_failed_url", True)),
                )
                return task_id
            finally:
                session.close()

        try:
            job = runner.start("resume", f"续跑任务 #{task_id}", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job": _job_data(job)}

    @app.post("/api/tools/install")
    async def install_tools(request: Request) -> dict[str, Any]:
        """Download only user-selected local prerequisites from the UI."""
        payload = await request.json()
        requested = payload.get("tools")
        if not isinstance(requested, list) or not requested:
            raise HTTPException(422, "请选择至少一个要安装的工具。")
        names = [str(name).strip().lower() for name in requested]
        supported = {"subfinder", "dnsx", "nmap"}
        unknown = sorted(set(names) - supported)
        if unknown:
            raise HTTPException(422, f"不支持从页面安装：{', '.join(unknown)}")

        def work(progress: Callable[[str], None]) -> None:
            config = load_config(path)
            ToolInstallService(Path(config.tools.tools_dir), progress).run(names)

        try:
            job = runner.start("install-tools", f"安装工具：{', '.join(names)}", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job": _job_data(job)}

    @app.get("/api/jobs")
    def list_jobs() -> dict[str, Any]:
        return {"jobs": [_job_data(job, include_lines=False) for job in runner.list()]}

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = runner.get(job_id)
        if not job:
            raise HTTPException(404, "未找到该页面任务。")
        return {"job": _job_data(job)}

    @app.get("/api/tasks/{task_id}/package")
    def download_package(task_id: int) -> FileResponse:
        config = load_config(path)
        engine = create_db_and_engine(config.database_url)
        session = get_session(engine)
        try:
            task = session.get(ScanTask, task_id)
            if not task:
                raise HTTPException(404, "未找到任务。")
            package = Path("deliveries") / f"task_{task.id}_{_safe_name(task.target)}.zip"
            if not package.exists():
                raise HTTPException(404, "交付包尚未生成。")
            return FileResponse(package, filename=package.name)
        finally:
            session.close()

    return app


def _job_data(job: UiJob, include_lines: bool = True) -> dict[str, Any]:
    payload = {
        "id": job.id,
        "kind": job.kind,
        "label": job.label,
        "status": job.status,
        "task_id": job.task_id,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
    }
    if include_lines:
        payload["lines"] = job.lines
    return payload
