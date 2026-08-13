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
from assetmap.services.delivery.quality import DeliveryQualityService
from assetmap.services.delivery.package import DeliveryPackageService, DeliveryPackageVerifier
from assetmap.services.runtime.environment import EnvironmentCheckService
from assetmap.stages import pipeline as stage_pipeline

from .common import (
    _exit_interrupted,
    _warn_environment,
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
        engine = create_db_and_engine(config.database_url)
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
        engine = create_db_and_engine(config.database_url)
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
        engine = create_db_and_engine(config.database_url)
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
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    ):
        config = load_config(config_path)
        engine = create_db_and_engine(config.database_url)
        session = get_session(engine)
        try:
            _warn_environment(
                config,
                include_subdomain_tools=False,
                include_nmap=True,
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
        engine = create_db_and_engine(config.database_url)
        session = get_session(engine)
        try:
            _warn_environment(config, include_subdomain_tools=False, include_httpx=True)
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
        engine = create_db_and_engine(config.database_url)
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
        rerun_urls: bool = typer.Option(False, "--rerun-urls", help="强制重跑 URL 入口和页面识别，并刷新报告。"),
        rerun_ai: bool = typer.Option(False, "--rerun-ai", help="强制重算报告中的 AI 分块分析。"),
        no_ai: bool = typer.Option(False, "--no-ai", help="子域名/DNS 阶段不调用 AI 推理。"),
        retry_failed_url: bool = typer.Option(True, "--retry-failed/--no-retry-failed", help="URL 阶段默认只补跑失败或缺失页面识别的入口。"),
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", help="配置文件路径。"),
    ):
        """按流水线状态自动续跑资产测绘流程。"""
        config = load_config(config_path)
        engine = create_db_and_engine(config.database_url)
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

    @app.command("pipeline")
    def unified_pipeline_command(
        target: str | None = typer.Argument(None, help="新建或续跑的目标企业名称。"),
        task_id: int | None = typer.Option(None, "--task-id", help="已有任务 ID。"),
        fresh: bool = typer.Option(False, "--fresh", help="重新执行企业发现，并刷新后续阶段。"),
        manual_file: Path | None = typer.Option(None, "--manual-file", "-m", help="导入人工补充资产后继续。"),
        from_stage: str = typer.Option("enterprise-discovery", "--from-stage"),
        to_stage: str = typer.Option("report-generation", "--to-stage"),
        rerun: bool = typer.Option(False, "--rerun", help="重跑所选范围内的已完成阶段。"),
        rerun_tools: bool = typer.Option(False, "--rerun-tools"),
        rerun_dns: bool = typer.Option(False, "--rerun-dns"),
        rerun_ports: bool = typer.Option(False, "--rerun-ports"),
        rerun_classify: bool = typer.Option(False, "--rerun-classify"),
        rerun_urls: bool = typer.Option(False, "--rerun-urls"),
        rerun_ai: bool = typer.Option(False, "--rerun-ai"),
        no_ai: bool = typer.Option(False, "--no-ai", help="域名阶段跳过 AI 源站判断。"),
        retry_failed: bool = typer.Option(False, "--retry-failed", help="仅重试实际失败的页面识别。"),
        output_dir: Path = typer.Option(Path("reports"), "--output-dir"),
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    ):
        """用同一条生产路径串联全部独立阶段；各阶段仍可单独执行。"""
        config = load_config(config_path)
        try:
            result = stage_pipeline.run(
                config,
                target=target,
                task_id=task_id,
                fresh=fresh,
                manual_file=manual_file,
                from_stage=from_stage,
                to_stage=to_stage,
                rerun=rerun,
                rerun_tools=rerun_tools,
                rerun_dns=rerun_dns,
                rerun_ports=rerun_ports,
                rerun_classify=rerun_classify,
                rerun_urls=rerun_urls,
                rerun_ai=rerun_ai,
                skip_ai=no_ai,
                retry_failed=retry_failed,
                output_dir=output_dir,
                progress=typer.echo,
            )
            typer.echo(
                f"[pipeline] 完成：task_id={result.task_id}，"
                f"执行={','.join(result.executed) or '无'}，"
                f"跳过={','.join(result.skipped) or '无'}。"
            )
        except KeyboardInterrupt:
            _exit_interrupted()


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
    # Keep the one-click command on the same public stage boundary as
    # ``assetmap pipeline`` and ``assetmap run``.  The surrounding CLI session
    # remains responsible only for the optional manual checkpoint and package.
    result = stage_pipeline.enterprise_discovery.run(
        config,
        target=target,
        task_id=resume_task,
        fresh=refresh,
        progress=progress,
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
    """Compatibility wrapper: normal CLI resume uses the standalone stages."""
    stage_pipeline.run(
        config,
        task_id=task_id,
        manual_file=manual_file,
        from_stage=from_stage,
        to_stage=to_stage,
        rerun=rerun,
        rerun_tools=rerun_subdomain_tools,
        rerun_dns=rerun_dns,
        rerun_ports=rerun_ports,
        rerun_classify=rerun_classify,
        rerun_urls=rerun_urls,
        rerun_ai=rerun_ai,
        skip_ai=no_ai,
        retry_failed=retry_failed_url,
        force_changed=force_changed,
        progress=progress,
    )


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
