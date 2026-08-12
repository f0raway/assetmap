"""报告和交付相关命令"""

from __future__ import annotations

from pathlib import Path

import typer

from assetmap.config import DEFAULT_CONFIG_PATH, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.delivery.report import ReportService
from assetmap.services.delivery.quality import DeliveryQualityService
from assetmap.services.delivery.package import DeliveryPackageService, DeliveryPackageVerifier

from .common import _exit_interrupted


def register(app: typer.Typer) -> None:
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
