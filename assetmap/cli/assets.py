"""资产导入导出相关命令"""

from __future__ import annotations

from pathlib import Path

import typer

from assetmap.config import DEFAULT_CONFIG_PATH, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.manual_import import (
    DEFAULT_MANUAL_ASSET_TEMPLATE_PATH,
    ManualAssetImportService,
    write_manual_asset_template,
)
from assetmap.services.gap_template import GapTemplateService
from assetmap.services.exporter import ExportService
from assetmap.services.maintenance import MaintenanceService
from assetmap.services.manual_asset_wizard import ManualAssetWizardService

from .common import _bootstrap, manual_import_next_command
from .pipeline import _run_pipeline


def register(app: typer.Typer) -> None:
    @app.command("add-asset")
    def add_asset_command(
        task_id: int,
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    ):
        """交互式逐条补充手动资产。"""
        _, _, session = _bootstrap(config_path)
        try:
            changed = ManualAssetWizardService(session, progress=typer.echo).run(task_id)
            if changed:
                typer.echo(f"Next: assetmap run {task_id} --from-stage subdomains")
            else:
                typer.echo("未添加资产。")
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
