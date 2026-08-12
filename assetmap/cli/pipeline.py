"""流水线相关命令"""

from __future__ import annotations

from pathlib import Path

import typer

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.acquisition.discovery import DiscoveryService
from assetmap.services.mapping.subdomain import SubdomainService
from assetmap.services.mapping.nmap_scan import NmapScanService
from assetmap.services.identification.asset_classifier import AssetClassifierService
from assetmap.services.identification.url_discovery import UrlDiscoveryService
from assetmap.services.delivery.report import ReportService
from assetmap.services.delivery.quality import DeliveryQualityService
from assetmap.services.delivery.package import DeliveryPackageService, DeliveryPackageVerifier
from assetmap.services.acquisition.manual_import import ManualAssetImportService
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.runtime.environment import EnvironmentCheckService

from .common import (
    _exit_interrupted,
    _warn_environment,
    _selected_pipeline_stages,
    _stage_status_map,
    _should_run_stage,
    _has_visual_gaps,
    _csv_values,
    PIPELINE_STAGES,
)


def register(app: typer.Typer) -> None:
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
        no_manual_prompt: bool = typer.Option(False, "--no-manual-prompt", help="跳过 discover 后的手动补充询问。"),
        manual_add: bool = typer.Option(False, "--manual-add", help="discover 后直接进入 TUI 补充资产。"),
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
                no_manual_prompt=no_manual_prompt,
                manual_add=manual_add,
                no_ai=no_ai,
                strict=strict,
                progress=typer.echo,
            )
        except KeyboardInterrupt:
            _exit_interrupted()
        finally:
            session.close()

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


def _run_one_click_scan(
    session,
    config: AppConfig,
    target: str | None,
    *,
    resume_task: int | None = None,
    refresh: bool = False,
    manual_file: Path | None = None,
    no_manual_prompt: bool = False,
    manual_add: bool = False,
    no_ai: bool = False,
    strict: bool = False,
    progress,
) -> int:
    _require_full_scan_environment(config, progress)
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

    # discover 后交互检查点：询问是否手动补充资产
    manual_imported = False
    if not manual_file and not no_manual_prompt:
        manual_imported = _prompt_manual_asset_import(
            session,
            config,
            result.task_id,
            result.company_count,
            result.asset_count,
            force_add=manual_add,
            progress=progress,
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
        force_changed=bool(manual_file) or manual_imported,
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


def _require_full_scan_environment(config: AppConfig, progress) -> None:
    """Fail before discovery when the configured full pipeline cannot run."""
    failures = [row for row in EnvironmentCheckService(config).check() if not row["ok"]]
    if not failures:
        return
    progress("[scan] preflight failed; no external collection was started.")
    for row in failures:
        progress(f"[scan] missing {row['name']}: {row['detail']}")
        if row["suggestion"]:
            progress(f"[scan] suggestion: {row['suggestion']}")
    raise typer.Exit(2)


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


def _prompt_manual_asset_import(
    session,
    config: AppConfig,
    task_id: int,
    company_count: int,
    asset_count: int,
    force_add: bool = False,
    progress=None,
) -> bool:
    """discover 后询问是否手动补充资产"""
    import questionary
    from questionary import Style

    custom_style = Style([
        ("qmark", "fg:cyan bold"),
        ("question", "bold"),
        ("answer", "fg:green bold"),
        ("pointer", "fg:cyan bold"),
    ])

    progress("")
    progress("=" * 50)
    progress("  企业资产采集完成")
    progress("=" * 50)
    progress("")
    progress(f"发现公司: {company_count} 家")
    progress(f"发现资产: {asset_count} 条")
    progress("")

    if force_add:
        # 直接进入 TUI 补充
        choice = "逐条添加资产"
    else:
        choice = questionary.select(
            "是否手动补充资产？",
            choices=[
                "跳过，继续自动流程",
                "逐条添加资产",
                "从文件批量导入",
            ],
            style=custom_style,
        ).ask()

    if choice == "跳过，继续自动流程":
        progress("○ 跳过手动补充")
        return False
    elif choice == "逐条添加资产":
        # 调用手动资产添加 TUI
        from assetmap.services.acquisition.manual_asset_wizard import ManualAssetWizardService
        wizard = ManualAssetWizardService(session, progress=progress)
        return wizard.run(task_id)
    elif choice == "从文件批量导入":
        file_path = questionary.path(
            "请输入资产文件路径:",
            style=custom_style,
        ).ask()
        if file_path and Path(file_path).exists():
            from assetmap.services.acquisition.manual_import import ManualAssetImportService
            service = ManualAssetImportService(session, progress=progress)
            result = service.run(task_id, Path(file_path))
            progress(f"✓ 已导入: {result.domains} 域名, {result.subdomains} 子域名, {result.ips} IP, {result.urls} URL")
            return True
        else:
            progress("✗ 文件不存在，跳过导入")
            return False
    return False
