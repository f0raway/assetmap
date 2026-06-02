from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import httpx
import typer
from sqlmodel import select

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config, write_sample_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import Company, CompanyAssetLink, CompanyEdge, InternetAsset, ScanTask
from assetmap.services.ai_client import chat_completion
from assetmap.services.asset_classifier import AssetClassifierService
from assetmap.services.discovery import DiscoveryService
from assetmap.services.environment import EnvironmentCheckService
from assetmap.services.exporter import ExportService
from assetmap.services.gap_template import GapTemplateService
from assetmap.services.improvement_plan import ImprovementPlanService
from assetmap.services.manual_import import (
    DEFAULT_MANUAL_ASSET_TEMPLATE_PATH,
    ManualAssetImportService,
    write_manual_asset_template,
)
from assetmap.services.maintenance import MaintenanceService
from assetmap.services.nmap_scan import NmapScanService
from assetmap.services.package import DeliveryPackageService, DeliveryPackageVerifier
from assetmap.services.quality import DeliveryQualityService
from assetmap.services.report import ReportService
from assetmap.services.review_import import ReviewImportService
from assetmap.services.review_workorder import ReviewWorkOrderService
from assetmap.services.status import PipelineStatusService
from assetmap.services.subdomain import SubdomainService
from assetmap.services.tool_resolver import ToolResolver
from assetmap.services.url_discovery import UrlDiscoveryService


app = typer.Typer(help="互联网数字资产暴露面测绘系统 v1")
PIPELINE_STAGES = ("subdomains", "port-scan", "classify", "url-discover", "report")


def _exit_interrupted() -> None:
    typer.echo("", err=True)
    typer.echo("[interrupt] Ctrl+C received. Task interrupted; partial data is kept in the database.", err=True)
    raise typer.Exit(130)


def _bootstrap(config_path: Path = DEFAULT_CONFIG_PATH):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    return config, engine, session


def _csv_values(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


@app.command("init")
def init_command(
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    force: bool = typer.Option(False, "--force"),
):
    config_exists = config_path.exists()
    path = write_sample_config(config_path, overwrite=force)
    manual_template = write_manual_asset_template()
    config = load_config(path)
    create_db_and_engine(config.database.url)
    if config_exists and not force:
        typer.echo(f"Config exists, kept unchanged: {path}")
    else:
        typer.echo(f"Initialized config: {path}")
    typer.echo(f"Initialized manual asset template: {manual_template}")
    typer.echo(f"Initialized database: {config.database.url}")


@app.command("env-check")
def env_check_command(config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config")):
    config = load_config(config_path)
    results = EnvironmentCheckService(config).check()
    ok = True
    for result in results:
        status = "ok" if result["ok"] else "missing"
        typer.echo(f"[{status}] {result['name']}: {result['detail']}")
        if not result["ok"]:
            ok = False
            typer.echo(f"  suggestion: {result['suggestion']}")
    if not ok:
        raise typer.Exit(1)


@app.command("ai-check")
def ai_check_command(
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    if not config.ai.enabled:
        typer.echo("[ai] disabled in config.yaml", err=True)
        raise typer.Exit(1)
    messages = [
        {
            "role": "user",
            "content": "请简短回答：当前模型调用是否成功？",
        }
    ]
    try:
        response = chat_completion(
            config.ai,
            messages,
            temperature=0.2,
            max_completion_tokens=512,
        )
    except httpx.HTTPStatusError as exc:
        typer.echo(f"[ai] failed: HTTP {exc.response.status_code}", err=True)
        try:
            error = exc.response.json().get("error", {})
        except ValueError:
            error = {"message": exc.response.text[:500]}
        message = error.get("message") or error
        param = error.get("param")
        typer.echo(f"[ai] error: {message}", err=True)
        if param:
            typer.echo(f"[ai] param: {param}", err=True)
        raise typer.Exit(1)
    content = response.get("choices", [{}])[0].get("message", {}).get("content") or ""
    typer.echo("[ai] chat completion ok")
    if content:
        typer.echo(content[:1000])


@app.command("discover")
def discover_command(
    target: str | None = typer.Argument(None),
    resume_task: int | None = typer.Option(None, "--resume-task"),
    refresh: bool = typer.Option(False, "--refresh", "--fresh"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        service = DiscoveryService(session, config, progress=typer.echo)
        result = service.run(target, resume_task_id=resume_task, fresh=refresh)
        typer.echo(f"Task {result.task_id} completed.")
        typer.echo("Data source: enscan_python")
        typer.echo(f"Companies discovered: {result.company_count}")
        typer.echo(f"Assets linked: {result.asset_count}")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("scan")
def scan_command(
    target: str | None = typer.Argument(None, help="目标公司名称。也可以配合 --resume-task 直接续跑已有任务。"),
    resume_task: int | None = typer.Option(None, "--resume-task", help="续跑已有任务 ID。"),
    refresh: bool = typer.Option(False, "--refresh", "--fresh", help="强制新建任务并重新采集企业/备案资产。"),
    manual_file: Path | None = typer.Option(None, "--manual-file", "-m", exists=True, readable=True, help="先导入人工补充资产，再纳入后续流程。"),
    no_ai: bool = typer.Option(False, "--no-ai", help="子域名/DNS 阶段不调用 AI 推理。"),
    strict: bool = typer.Option(False, "--strict", help="存在质量警告时不生成交付包。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", help="配置文件路径。"),
):
    """一键执行：企业采集 -> 子域名/DNS -> 端口 -> 服务/URL -> 报告 -> 打包校验。"""
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        _run_one_click_scan(
            session,
            config,
            target,
            resume_task=resume_task,
            refresh=refresh,
            manual_file=manual_file,
            no_ai=no_ai,
            strict=strict,
            progress=typer.echo,
        )
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


def _run_one_click_scan(
    session,
    config: AppConfig,
    target: str | None,
    *,
    resume_task: int | None = None,
    refresh: bool = False,
    manual_file: Path | None = None,
    no_ai: bool = False,
    strict: bool = False,
    progress,
) -> int:
    progress("[scan] 1/3 discover enterprise tree and filing assets")
    result = DiscoveryService(session, config, progress=progress).run(
        target,
        resume_task_id=resume_task,
        fresh=refresh,
    )
    progress(
        f"[scan] discovered task={result.task_id}, companies={result.company_count}, "
        f"assets={result.asset_count}"
    )

    progress("[scan] 2/3 run mapping pipeline")
    _run_pipeline(
        session,
        config,
        result.task_id,
        progress=progress,
        manual_file=manual_file,
        from_stage="subdomains",
        to_stage="report",
        no_ai=no_ai,
        force_changed=bool(manual_file),
    )

    progress("[scan] 3/3 quality gate and delivery package")
    quality = DeliveryQualityService(session, config).check(result.task_id, output_dir=Path("reports"))
    progress(f"[scan] quality -> {quality.status}")
    for warning in quality.warnings:
        progress(f"[scan] warning: {warning}")
    if quality.failures:
        for failure in quality.failures:
            progress(f"[scan] failure: {failure}")
        raise typer.Exit(1)
    if strict and quality.warnings:
        progress("[scan] strict mode stopped by quality warnings")
        raise typer.Exit(1)

    package = DeliveryPackageService(session, config).package(
        result.task_id,
        reports_dir=Path("reports"),
        output_dir=Path("deliveries"),
        strict=strict,
    )
    progress(f"[scan] package directory -> {package.package_dir}")
    progress(f"[scan] package zip -> {package.zip_path}")
    verification = DeliveryPackageVerifier().verify(package.zip_path)
    for line in verification.lines:
        progress(line)
    if verification.failures:
        raise typer.Exit(1)
    progress("[scan] completed")
    return result.task_id


@app.command("subdomains")
def subdomains_command(
    task_id: int,
    rerun_tools: bool = typer.Option(False, "--rerun-tools"),
    rerun_dns: bool = typer.Option(False, "--rerun-dns"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        _warn_environment(config, include_nmap=False)
        service = SubdomainService(session, config, progress=typer.echo)
        subtask_id = service.run(task_id, run_ai=not no_ai, rerun_tools=rerun_tools, rerun_dns=rerun_dns)
        typer.echo(f"Subdomain task {subtask_id} completed for scan task {task_id}.")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("import-assets")
def import_assets_command(
    task_id: int,
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True),
    continue_pipeline: bool = typer.Option(False, "--continue", "--run-pipeline", help="导入后立即续跑后续测绘流程。"),
    to_stage: str = typer.Option("report", "--to-stage", help="--continue 时运行到哪个阶段结束。"),
    no_ai: bool = typer.Option(False, "--no-ai", help="--continue 时子域名/DNS 阶段不调用 AI 推理。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config, _, session = _bootstrap(config_path)
    try:
        service = ManualAssetImportService(session, progress=typer.echo)
        result = service.run(task_id, file)
        typer.echo(f"Manual assets imported for scan task {task_id}.")
        typer.echo(f"Units in file: {result.units}")
        typer.echo(f"Units with filled asset fields: {result.units_with_input}")
        if result.empty_units:
            typer.echo(f"Units still empty: {len(result.empty_units)}")
            for unit in result.empty_units[:10]:
                typer.echo(f"- {unit}")
        typer.echo(f"Root domains linked: {result.domains}")
        typer.echo(f"Subdomains added: {result.subdomains}")
        typer.echo(f"Manual IPs added for port scan: {result.ips}")
        typer.echo(f"Manual URLs added for URL discovery: {result.urls}")
        typer.echo(f"Named assets linked: {result.assets}")
        typer.echo(f"No-asset review attestations: {result.no_asset_reviews}")
        typer.echo(f"Merged duplicate links: {result.merged_links}")
        typer.echo(f"Skipped invalid entries: {result.skipped}")
        for warning in (result.warnings or [])[:10]:
            typer.echo(f"- {warning}")
        if continue_pipeline:
            typer.echo("[manual] continue pipeline from subdomains")
            _run_pipeline(
                session,
                config,
                task_id,
                progress=typer.echo,
                from_stage="subdomains",
                to_stage=to_stage,
                no_ai=no_ai,
                force_changed=True,
            )
        else:
            typer.echo(f"Next: {manual_import_next_command(task_id, file)}")
    finally:
        session.close()


@app.command("asset-template")
def asset_template_command(
    output: Path = typer.Option(DEFAULT_MANUAL_ASSET_TEMPLATE_PATH, "--output", "-o"),
    force: bool = typer.Option(False, "--force"),
):
    path = write_manual_asset_template(output, overwrite=force)
    typer.echo(f"Manual asset template: {path}")


@app.command("asset-gap-template")
def asset_gap_template_command(
    task_id: int,
    output: Path = typer.Option(Path("data/manual_assets.gaps.yaml"), "--output", "-o"),
    include_partial: bool = typer.Option(False, "--include-partial", help="同时包含已有资产线索但尚未形成端口/Web覆盖的单位。"),
    priority: str = typer.Option("all", "--priority", help="导出优先级：all/high-medium/high/medium/low。"),
    force: bool = typer.Option(False, "--force"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config, _, session = _bootstrap(config_path)
    try:
        result = GapTemplateService(session, config).write(
            task_id,
            output,
            include_partial=include_partial,
            priority_filter=priority,
            force=force,
        )
        if result.skipped_existing:
            typer.echo(f"Gap asset template exists, kept unchanged: {result.path}")
        else:
            typer.echo(f"Gap asset template: {result.path}")
            typer.echo(f"Units needing supplement: {result.units}")
    finally:
        session.close()


@app.command("review-workorder")
def review_workorder_command(
    task_id: int,
    output: Path = typer.Option(Path("data/review_workorder.yaml"), "--output", "-o"),
    force: bool = typer.Option(False, "--force"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config, _, session = _bootstrap(config_path)
    try:
        result = ReviewWorkOrderService(session, config).write(task_id, output, force=force)
        if result.skipped_existing:
            typer.echo(f"Review workorder exists, kept unchanged: {result.path}")
        else:
            typer.echo(f"Review workorder: {result.path}")
            typer.echo(f"Total review items: {result.total_items}")
            typer.echo(
                "Breakdown: "
                f"asset={result.asset_items}, dns={result.dns_items}, service={result.service_items}, "
                f"url={result.url_items}, visual={result.visual_items}"
            )
    finally:
        session.close()


@app.command("import-review")
def import_review_command(
    task_id: int,
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    """导入复核工作单中的人工确认结果。"""
    _, _, session = _bootstrap(config_path)
    try:
        result = ReviewImportService(session).run(task_id, file)
        typer.echo(f"Review attestations imported for scan task {task_id}.")
        typer.echo(f"Imported: {result.imported}")
        typer.echo(f"Skipped pending: {result.skipped_pending}")
        typer.echo(f"Skipped invalid: {result.skipped_invalid}")
        for category, count in sorted(result.categories.items()):
            typer.echo(f"- {category}: {count}")
        typer.echo(f"Next: assetmap report {task_id}")
    finally:
        session.close()


@app.command("improvement-plan")
def improvement_plan_command(
    task_id: int,
    output_dir: Path = typer.Option(Path("data") / "improvement", "--output-dir", "-o"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config, _, session = _bootstrap(config_path)
    try:
        result = ImprovementPlanService(session, config).write(
            task_id,
            output_dir=output_dir,
            reports_dir=reports_dir,
        )
        typer.echo(f"Improvement plan JSON: {result.json_path}")
        typer.echo(f"Improvement plan text: {result.text_path}")
        typer.echo(f"Quality: {result.quality_status}")
        typer.echo(
            "Actions: "
            f"total={result.action_count}, automatic={result.automatic_actions}, manual={result.manual_actions}"
        )
    finally:
        session.close()


@app.command("improve")
def improve_command(
    task_id: int,
    execute: bool = typer.Option(False, "--execute", help="执行选中的补全动作；默认只预演。"),
    mode: str = typer.Option("automatic", "--mode", help="选择动作：automatic/manual/all。"),
    include_deliver: bool = typer.Option(False, "--include-deliver", help="执行模式下同时运行最终 deliver 动作。"),
    output_dir: Path = typer.Option(Path("data") / "improvement", "--output-dir", "-o"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    """按补全计划预演或执行下一轮补全动作。"""
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        result = ImprovementPlanService(session, config).write(
            task_id,
            output_dir=output_dir,
            reports_dir=reports_dir,
        )
        payload = json.loads(result.json_path.read_text(encoding="utf-8"))
        actions = _select_improve_actions(payload.get("actions", []), mode, include_deliver=include_deliver)
        typer.echo(f"[improve] plan json -> {result.json_path}")
        typer.echo(f"[improve] plan text -> {result.text_path}")
        typer.echo(f"[improve] quality -> {result.quality_status}")
        if not actions:
            typer.echo("[improve] no selected actions")
            return
        typer.echo("[improve] selected actions:")
        for action in actions:
            typer.echo(f"- {action.get('id')} {action.get('phase')} [{action.get('mode')}] -> {action.get('command')}")
        if not execute:
            typer.echo("[improve] dry-run only; add --execute to run selected actions")
            return
        execution_actions = _coalesce_improve_actions(actions)
        if [item.get("id") for item in execution_actions] != [item.get("id") for item in actions]:
            typer.echo("[improve] execution plan was consolidated to avoid duplicate downstream reruns:")
            for action in execution_actions:
                typer.echo(f"- {action.get('id')} {action.get('phase')}")
        _execute_improve_actions(session, config, task_id, execution_actions, reports_dir=reports_dir, progress=typer.echo)
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


def _select_improve_actions(actions: list[dict], mode: str, *, include_deliver: bool = False) -> list[dict]:
    selected_mode = mode.lower().strip()
    if selected_mode not in {"automatic", "manual", "all"}:
        raise typer.BadParameter("--mode must be automatic, manual, or all")
    selected = []
    for action in actions:
        phase = action.get("phase")
        if phase == "报告交付" and not include_deliver:
            continue
        action_mode = action.get("mode")
        if selected_mode == "all" or action_mode == selected_mode:
            selected.append(action)
    return selected


def _coalesce_improve_actions(actions: list[dict]) -> list[dict]:
    pipeline_rank = {
        "流程补齐": 0,
        "子域名/DNS": 1,
        "端口发现": 2,
        "服务识别/URL": 3,
        "URL视觉识别": 4,
    }
    manual = [action for action in actions if action.get("mode") == "manual"]
    deliver = [action for action in actions if action.get("phase") == "报告交付"]
    pipeline = [action for action in actions if action.get("phase") in pipeline_rank]
    selected_pipeline = []
    if pipeline:
        selected_pipeline = [min(pipeline, key=lambda item: pipeline_rank.get(item.get("phase"), 99))]
    return [*manual, *selected_pipeline, *deliver]


def _execute_improve_actions(
    session,
    config: AppConfig,
    task_id: int,
    actions: list[dict],
    *,
    reports_dir: Path,
    progress,
) -> None:
    review_workorder_written = False
    for action in actions:
        phase = action.get("phase")
        command = str(action.get("command") or "")
        progress(f"[improve] execute {action.get('id')} {phase}")
        if phase == "企业/备案资产":
            path = Path("data") / f"manual_assets.task_{task_id}.gaps.yaml"
            result = GapTemplateService(session, config).write(
                task_id,
                path,
                include_partial=True,
                priority_filter="high-medium",
                force=True,
            )
            progress(f"[improve] gap template -> {result.path} (units={result.units})")
            progress(f"[improve] fill it, then run: assetmap run {task_id} --manual-file {result.path}")
        elif phase == "流程补齐":
            _run_pipeline(session, config, task_id, progress=progress, from_stage="subdomains")
        elif phase == "子域名/DNS":
            if action.get("mode") == "manual":
                if not review_workorder_written:
                    _write_review_workorder_for_improve(session, config, task_id, progress)
                    review_workorder_written = True
                else:
                    progress("[improve] review workorder already generated; skip duplicate manual review action")
            else:
                _run_pipeline(
                    session,
                    config,
                    task_id,
                    progress=progress,
                    from_stage="subdomains",
                    rerun_subdomain_tools=True,
                )
        elif phase == "端口发现":
            original_sources = list(config.port_scan.sources_enabled)
            override_sources = _sources_from_action_command(command)
            if override_sources:
                config.port_scan.sources_enabled = override_sources
                progress(f"[improve] temporary port sources -> {','.join(override_sources)}")
            try:
                _run_pipeline(session, config, task_id, progress=progress, from_stage="port-scan", rerun_ports=True)
            finally:
                config.port_scan.sources_enabled = original_sources
        elif phase == "服务识别/URL":
            if action.get("mode") == "manual":
                if not review_workorder_written:
                    _write_review_workorder_for_improve(session, config, task_id, progress)
                    review_workorder_written = True
                else:
                    progress("[improve] review workorder already generated; skip duplicate manual review action")
            else:
                _run_pipeline(session, config, task_id, progress=progress, from_stage="classify", rerun_classify=True)
        elif phase == "URL视觉识别":
            if action.get("mode") == "manual":
                if not review_workorder_written:
                    _write_review_workorder_for_improve(session, config, task_id, progress)
                    review_workorder_written = True
                else:
                    progress("[improve] review workorder already generated; skip duplicate manual review action")
            else:
                UrlDiscoveryService(session, config, progress=progress).run(task_id, retry_failed=True)
                ReportService(session, config, progress=progress).run(task_id, output_dir=reports_dir)
        elif phase == "报告交付":
            report = ReportService(session, config, progress=progress).run(task_id, output_dir=reports_dir)
            progress(f"[improve] report -> {report.report_path}")
            package = DeliveryPackageService(session, config).package(task_id, reports_dir=reports_dir)
            progress(f"[improve] package -> {package.zip_path}")
            verification = DeliveryPackageVerifier().verify(package.zip_path)
            for line in verification.lines:
                progress(line)
        else:
            progress(f"[improve] skip unsupported phase: {phase}")


def _write_review_workorder_for_improve(session, config: AppConfig, task_id: int, progress) -> None:
    path = Path("data") / f"review_workorder.task_{task_id}.yaml"
    result = ReviewWorkOrderService(session, config).write(task_id, path, force=True)
    progress(f"[improve] review workorder -> {result.path} (items={result.total_items})")
    progress(f"[improve] fill review_status, then run: assetmap import-review {task_id} --file {path}")


def _sources_from_action_command(command: str) -> list[str] | None:
    parts = command.split()
    if "--sources" not in parts:
        return None
    index = parts.index("--sources")
    if index + 1 >= len(parts):
        return None
    return _csv_values(parts[index + 1])


@app.command("nmap-scan")
@app.command("port-scan")
def port_scan_command(
    task_id: int,
    rerun: bool = typer.Option(False, "--rerun"),
    sources: str | None = typer.Option(None, "--sources", help="临时覆盖端口发现来源，例如 nmap、fofa 或 nmap,fofa。"),
    target_sources: str | None = typer.Option(None, "--target-sources", help="临时覆盖端口目标来源，例如 ai,manual,dns_public。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    override_sources = _csv_values(sources)
    override_target_sources = _csv_values(target_sources)
    if override_sources is not None:
        config.port_scan.sources_enabled = override_sources
    if override_target_sources is not None:
        config.port_scan.target_sources_enabled = override_target_sources
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        _warn_environment(
            config,
            include_subdomain_tools=False,
            include_nmap="nmap" in {source.lower().strip() for source in config.port_scan.sources_enabled},
        )
        service = NmapScanService(session, config, progress=typer.echo)
        nmap_task_id = service.run(task_id, rerun=rerun)
        typer.echo(f"Port scan task {nmap_task_id} completed for scan task {task_id}.")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("classify")
def classify_command(
    task_id: int,
    rerun: bool = typer.Option(False, "--rerun"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        _warn_environment(config, include_subdomain_tools=False)
        service = AssetClassifierService(session, config, progress=typer.echo)
        classify_task_id = service.run(task_id, rerun=rerun)
        typer.echo(f"Classification task {classify_task_id} completed for scan task {task_id}.")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("url-discover")
def url_discover_command(
    task_id: int,
    rerun: bool = typer.Option(False, "--rerun"),
    retry_failed: bool = typer.Option(False, "--retry-failed"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        typer.echo(
            "[url] purpose: seed URL entrypoints from classified web services, "
            "then screenshot pages and use AI to identify system names and site purpose."
        )
        service = UrlDiscoveryService(session, config, progress=typer.echo)
        url_task_id = service.run(task_id, rerun=rerun, retry_failed=retry_failed)
        typer.echo(f"URL discovery task {url_task_id} completed for scan task {task_id}.")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("run")
def run_command(
    task_id: int,
    manual_file: Path | None = typer.Option(
        None,
        "--manual-file",
        "-m",
        exists=True,
        readable=True,
        help="先导入人工补充资产，再继续后续流程。",
    ),
    from_stage: str = typer.Option("subdomains", "--from-stage", help="从哪个阶段开始：subdomains/port-scan/classify/url-discover/report。"),
    to_stage: str = typer.Option("report", "--to-stage", help="运行到哪个阶段结束。"),
    rerun: bool = typer.Option(False, "--rerun", help="强制重跑选择范围内的所有阶段。"),
    rerun_subdomain_tools: bool = typer.Option(False, "--rerun-subdomain-tools", help="强制重跑子域名主动/被动枚举工具，并刷新 DNS 与后续阶段。"),
    rerun_dns: bool = typer.Option(False, "--rerun-dns", help="强制重跑子域名阶段的 DNS 解析，并刷新后续阶段。"),
    rerun_ports: bool = typer.Option(False, "--rerun-ports", help="强制重跑端口发现，并刷新后续阶段。"),
    rerun_classify: bool = typer.Option(False, "--rerun-classify", help="强制重跑服务识别，并刷新 URL 识别和报告。"),
    rerun_urls: bool = typer.Option(False, "--rerun-urls", help="强制重跑 URL 入口和视觉识别，并刷新报告。"),
    rerun_ai: bool = typer.Option(False, "--rerun-ai", help="强制重算报告中的 AI 分块分析。"),
    no_ai: bool = typer.Option(False, "--no-ai", help="子域名/DNS 阶段不调用 AI 推理。"),
    retry_failed_url: bool = typer.Option(True, "--retry-failed/--no-retry-failed", help="URL 阶段默认只补跑失败或缺失视觉识别的页面。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", help="配置文件路径。"),
):
    """按流水线状态自动续跑资产测绘流程。"""
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        _run_pipeline(
            session,
            config,
            task_id,
            progress=typer.echo,
            manual_file=manual_file,
            from_stage=from_stage,
            to_stage=to_stage,
            rerun=rerun,
            rerun_subdomain_tools=rerun_subdomain_tools,
            rerun_dns=rerun_dns,
            rerun_ports=rerun_ports,
            rerun_classify=rerun_classify,
            rerun_urls=rerun_urls,
            rerun_ai=rerun_ai,
            no_ai=no_ai,
            retry_failed_url=retry_failed_url,
        )
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


def _run_pipeline(
    session,
    config: AppConfig,
    task_id: int,
    *,
    progress,
    manual_file: Path | None = None,
    from_stage: str = "subdomains",
    to_stage: str = "report",
    rerun: bool = False,
    rerun_subdomain_tools: bool = False,
    rerun_dns: bool = False,
    rerun_ports: bool = False,
    rerun_classify: bool = False,
    rerun_urls: bool = False,
    rerun_ai: bool = False,
    no_ai: bool = False,
    retry_failed_url: bool = True,
    force_changed: bool = False,
) -> None:
    selected = _selected_pipeline_stages(from_stage, to_stage)
    progress(f"[run] task={task_id}, stages={','.join(selected)}")
    if manual_file:
        progress(f"[run] import manual assets -> {manual_file}")
        ManualAssetImportService(session, progress=progress).run(task_id, manual_file)
    changed = bool(manual_file) or force_changed
    stage_status = _stage_status_map(session, task_id)
    if "subdomains" in selected and _should_run_stage(stage_status, "subdomains", rerun or rerun_subdomain_tools or rerun_dns or changed):
        _warn_environment(config, include_nmap=False)
        SubdomainService(session, config, progress=progress).run(
            task_id,
            run_ai=not no_ai,
            rerun_tools=rerun or rerun_subdomain_tools,
            rerun_dns=rerun or rerun_subdomain_tools or rerun_dns,
        )
        changed = True
    else:
        progress("[run] skip subdomains")
    stage_status = _stage_status_map(session, task_id)
    if "port-scan" in selected and _should_run_stage(stage_status, "port-scan", rerun or rerun_ports or changed):
        _warn_environment(
            config,
            include_subdomain_tools=False,
            include_nmap="nmap" in {source.lower().strip() for source in config.port_scan.sources_enabled},
        )
        NmapScanService(session, config, progress=progress).run(task_id, rerun=rerun or rerun_ports or changed)
        changed = True
    else:
        progress("[run] skip port-scan")
    stage_status = _stage_status_map(session, task_id)
    if "classify" in selected and _should_run_stage(stage_status, "classify", rerun or rerun_classify or changed):
        _warn_environment(config, include_subdomain_tools=False)
        AssetClassifierService(session, config, progress=progress).run(task_id, rerun=rerun or rerun_classify or changed)
        changed = True
    else:
        progress("[run] skip classify")
    stage_status = _stage_status_map(session, task_id)
    run_url = _should_run_stage(stage_status, "url-discover", rerun or rerun_urls or changed)
    if not run_url and retry_failed_url:
        run_url = _has_visual_gaps(session, task_id)
    if "url-discover" in selected and run_url:
        progress(
            "[url] purpose: seed URL entrypoints from classified web services, "
            "then screenshot pages and use AI to identify system names and site purpose."
        )
        UrlDiscoveryService(session, config, progress=progress).run(
            task_id,
            rerun=rerun or rerun_urls or changed,
            retry_failed=retry_failed_url and not rerun,
        )
        changed = True
    else:
        progress("[run] skip url-discover")
    stage_status = _stage_status_map(session, task_id)
    if "report" in selected and _should_run_stage(stage_status, "report", rerun or rerun_ai or changed):
        result = ReportService(session, config, progress=progress).run(task_id, rerun_ai=rerun or rerun_ai or changed)
        progress(f"Report generated: {result.report_path}")
        progress(f"Attachment generated: {result.asset_workbook_path}")
        progress(f"Attachment generated: {result.web_workbook_path}")
    else:
        progress("[run] skip report")
    progress("[run] final status")
    status = PipelineStatusService(session).get(task_id)
    for line in status.lines:
        progress(line)


def manual_import_next_command(task_id: int, file: Path | str) -> str:
    return f"assetmap run {task_id} --manual-file {_command_path(file)}"


def _command_path(path: Path | str) -> str:
    text = str(path)
    if any(char.isspace() for char in text):
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'
    return text


def _selected_pipeline_stages(from_stage: str, to_stage: str) -> tuple[str, ...]:
    start = from_stage.lower().strip()
    end = to_stage.lower().strip()
    aliases = {"nmap": "port-scan", "nmap-scan": "port-scan", "url": "url-discover"}
    start = aliases.get(start, start)
    end = aliases.get(end, end)
    if start not in PIPELINE_STAGES:
        raise typer.BadParameter(f"Unsupported --from-stage: {from_stage}")
    if end not in PIPELINE_STAGES:
        raise typer.BadParameter(f"Unsupported --to-stage: {to_stage}")
    start_index = PIPELINE_STAGES.index(start)
    end_index = PIPELINE_STAGES.index(end)
    if start_index > end_index:
        raise typer.BadParameter("--from-stage must be before or equal to --to-stage")
    return PIPELINE_STAGES[start_index : end_index + 1]


def _stage_status_map(session, task_id: int) -> dict[str, str]:
    status = PipelineStatusService(session).get(task_id)
    return {name: stage_status for name, stage_status, _ in status.stages}


def _should_run_stage(stage_status: dict[str, str], stage: str, force: bool = False) -> bool:
    if force:
        return True
    return stage_status.get(stage) not in {"completed", "skipped"}


def _has_visual_gaps(session, task_id: int) -> bool:
    from assetmap.models import WebEntrypoint

    rows = session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == task_id)).all()
    return any(
        not (row.evidence or {}).get("visual_analysis")
        for row in rows
    )


def _warn_environment(
    config: AppConfig,
    include_subdomain_tools: bool = True,
    include_nmap: bool = True,
) -> None:
    resolver = ToolResolver(config.tools)
    results = resolver.check_environment(
        include_subdomain_tools=include_subdomain_tools,
        include_nmap=include_nmap,
    )
    for result in results:
        if not result["ok"]:
            typer.echo(f"[env] missing {result['name']}: {result['detail']}", err=True)
            typer.echo(f"[env] suggestion: {result['suggestion']}", err=True)


@app.command("show")
def show_command(
    task_id: int,
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    _, _, session = _bootstrap(config_path)
    try:
        task = session.get(ScanTask, task_id)
        if not task:
            raise typer.Exit(f"Task not found: {task_id}")
        companies = {company.id: company for company in session.exec(select(Company)).all()}
        edges = session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        links = session.exec(select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id)).all()
        assets = {
            asset.id: asset
            for asset in session.exec(
                select(InternetAsset).where(
                    InternetAsset.id.in_(select(CompanyAssetLink.asset_id).where(CompanyAssetLink.task_id == task_id))
                )
            ).all()
        }
        children = defaultdict(list)
        child_ids = set()
        for edge in edges:
            children[edge.parent_company_id].append(edge)
            child_ids.add(edge.child_company_id)
        roots = [company_id for company_id in children.keys() if company_id not in child_ids]
        task_company_ids = {edge.parent_company_id for edge in edges} | {edge.child_company_id for edge in edges}
        task_company_ids.update(link.company_id for link in links)
        typer.echo(f"Task: {task.id}")
        typer.echo(f"Target: {task.target}")
        typer.echo(f"Status: {task.status}")
        typer.echo(f"Company count: {len(task_company_ids)}")
        typer.echo("Organization tree:")
        if roots:
            for root_id in roots:
                _print_tree(root_id, children, companies, prefix="", print_self=True)
        elif task_company_ids:
            for company_id in sorted(task_company_ids):
                typer.echo(companies[company_id].name)
        unique_assets = {
            (link.company_id, link.asset_id): assets[link.asset_id]
            for link in links
            if link.asset_id in assets
        }
        counts = Counter(asset.asset_type for asset in unique_assets.values())
        typer.echo("Asset summary:")
        for asset_type, count in sorted(counts.items()):
            typer.echo(f"- {asset_type}: {count}")
    finally:
        session.close()


@app.command("status")
def status_command(
    task_id: int,
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config, _, session = _bootstrap(config_path)
    try:
        status = PipelineStatusService(session).get(task_id)
        for line in status.lines:
            typer.echo(line)
        if status.next_step:
            typer.echo("")
            typer.echo(f"Next suggested command: {status.next_step.replace('<task_id>', str(task_id))}")
        else:
            quality = DeliveryQualityService(session, config).check(task_id)
            typer.echo("")
            if quality.status == "PASS":
                typer.echo("Next suggested command: none, pipeline appears complete and quality gates passed.")
            else:
                typer.echo(f"Quality status: {quality.status}")
                actions = _quality_suggested_actions(quality.lines)
                if actions:
                    typer.echo("Next suggested actions:")
                    for action in actions:
                        typer.echo(f"- {action}")
                else:
                    typer.echo(f"Next suggested action: assetmap quality-check {task_id}")
    finally:
        session.close()


def _quality_suggested_actions(lines: list[str]) -> list[str]:
    actions: list[str] = []
    capture = False
    for line in lines:
        text = line.strip()
        if text == "Suggested next actions:":
            capture = True
            continue
        if not capture:
            continue
        if text.startswith("- "):
            actions.append(text[2:])
        elif text:
            break
    return actions


def _print_tree(root_id: int, children, companies, prefix: str, print_self: bool = False):
    company = companies.get(root_id)
    if company and print_self:
        typer.echo(f"{prefix}{company.name}")
    for edge in sorted(children.get(root_id, []), key=lambda item: item.depth):
        child = companies.get(edge.child_company_id)
        if not child:
            continue
        typer.echo(f"{prefix}  -> {child.name} ({edge.direct_holding_ratio:.2%}, cum {edge.cumulative_holding_ratio:.2%})")
        _print_tree(edge.child_company_id, children, companies, prefix + "     ", print_self=False)


@app.command("dedupe-assets")
def dedupe_assets_command(
    task_id: int,
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    _, _, session = _bootstrap(config_path)
    try:
        result = MaintenanceService(session).dedupe_asset_links(task_id)
        typer.echo(f"Asset links deduped for scan task {task_id}.")
        typer.echo(f"Duplicate links removed: {result.removed_links}")
    finally:
        session.close()


@app.command("export")
def export_command(
    task_id: int,
    format: str = typer.Option(..., "--format", case_sensitive=False),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    _, _, session = _bootstrap(config_path)
    try:
        service = ExportService(session)
        path = service.export(task_id, format.lower())
        typer.echo(f"Exported to: {path}")
    finally:
        session.close()


@app.command("report")
def report_command(
    task_id: int,
    output_dir: Path = typer.Option(Path("reports"), "--output-dir", "-o"),
    rerun_ai: bool = typer.Option(False, "--rerun-ai"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        service = ReportService(session, config, progress=typer.echo)
        result = service.run(task_id, output_dir=output_dir, rerun_ai=rerun_ai)
        typer.echo(f"Report generated: {result.report_path}")
        typer.echo(f"Attachment generated: {result.asset_workbook_path}")
        typer.echo(f"Attachment generated: {result.web_workbook_path}")
        typer.echo(f"AI analysis sections: {result.analysis_count}")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("deliver")
def deliver_command(
    task_id: int,
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    output_dir: Path = typer.Option(Path("deliveries"), "--output-dir", "-o"),
    rerun_ai: bool = typer.Option(False, "--rerun-ai", help="强制重算报告中的 AI 分块分析。"),
    strict: bool = typer.Option(False, "--strict", help="存在质量警告时不生成交付包。"),
    include_partial_gaps: bool = typer.Option(True, "--include-partial-gaps/--no-include-partial-gaps", help="待补充模板包含部分覆盖单位。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    """生成报告、执行质量门禁、打包并校验交付压缩包。"""
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        typer.echo("[deliver] step 1/4 report")
        report = ReportService(session, config, progress=typer.echo).run(
            task_id,
            output_dir=reports_dir,
            rerun_ai=rerun_ai,
        )
        typer.echo(f"[deliver] report -> {report.report_path}")
        typer.echo(f"[deliver] asset workbook -> {report.asset_workbook_path}")
        typer.echo(f"[deliver] web workbook -> {report.web_workbook_path}")

        typer.echo("[deliver] step 2/4 quality-check")
        quality = DeliveryQualityService(session, config).check(task_id, output_dir=reports_dir)
        typer.echo(f"[deliver] quality -> {quality.status}")
        for warning in quality.warnings:
            typer.echo(f"[deliver] warning: {warning}")
        if quality.failures:
            for failure in quality.failures:
                typer.echo(f"[deliver] failure: {failure}", err=True)
            raise typer.Exit(1)
        if strict and quality.warnings:
            typer.echo("[deliver] strict mode stopped by quality warnings", err=True)
            raise typer.Exit(1)

        typer.echo("[deliver] step 3/4 package")
        package = DeliveryPackageService(session, config).package(
            task_id,
            reports_dir=reports_dir,
            output_dir=output_dir,
            include_partial_gaps=include_partial_gaps,
            strict=strict,
        )
        typer.echo(f"[deliver] package directory -> {package.package_dir}")
        typer.echo(f"[deliver] package zip -> {package.zip_path}")

        typer.echo("[deliver] step 4/4 verify")
        verification = DeliveryPackageVerifier().verify(package.zip_path)
        for line in verification.lines:
            typer.echo(line)
        if verification.failures:
            raise typer.Exit(1)
        typer.echo("[deliver] completed")
    except KeyboardInterrupt:
        _exit_interrupted()
    finally:
        session.close()


@app.command("quality-check")
@app.command("report-check")
def quality_check_command(
    task_id: int,
    output_dir: Path = typer.Option(Path("reports"), "--output-dir", "-o"),
    strict: bool = typer.Option(False, "--strict", help="存在警告时也返回失败状态。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        result = DeliveryQualityService(session, config).check(task_id, output_dir=output_dir)
        for line in result.lines:
            typer.echo(line)
        if result.failures or (strict and result.warnings):
            raise typer.Exit(1)
    finally:
        session.close()


@app.command("package-report")
def package_report_command(
    task_id: int,
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    output_dir: Path = typer.Option(Path("deliveries"), "--output-dir", "-o"),
    strict: bool = typer.Option(False, "--strict", help="存在质量警告时不打包。"),
    no_gap_template: bool = typer.Option(False, "--no-gap-template", help="不在交付包中生成待补充资产模板。"),
    no_review_workorder: bool = typer.Option(False, "--no-review-workorder", help="不在交付包中生成复核工作单。"),
    include_partial_gaps: bool = typer.Option(True, "--include-partial-gaps/--no-include-partial-gaps", help="待补充模板包含部分覆盖单位。"),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
):
    config = load_config(config_path)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    try:
        result = DeliveryPackageService(session, config).package(
            task_id,
            reports_dir=reports_dir,
            output_dir=output_dir,
            include_gap_template=not no_gap_template,
            include_review_workorder=not no_review_workorder,
            include_partial_gaps=include_partial_gaps,
            strict=strict,
        )
        typer.echo(f"Delivery package directory: {result.package_dir}")
        typer.echo(f"Delivery package zip: {result.zip_path}")
        typer.echo(f"Manifest: {result.manifest_path}")
        typer.echo(f"Quality: {result.quality_status}")
        typer.echo(f"Files packaged: {len(result.packaged_files)}")
    except ValueError as exc:
        typer.echo(f"[package] {exc}", err=True)
        raise typer.Exit(1)
    finally:
        session.close()


@app.command("verify-package")
def verify_package_command(
    package_path: Path = typer.Argument(..., exists=True),
):
    result = DeliveryPackageVerifier().verify(package_path)
    for line in result.lines:
        typer.echo(line)
    if result.failures:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
