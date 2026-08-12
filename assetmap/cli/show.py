"""状态查看相关命令"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import typer
from sqlmodel import select

from assetmap.config import DEFAULT_CONFIG_PATH, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import Company, CompanyAssetLink, CompanyEdge, InternetAsset, ScanTask
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.delivery.quality import DeliveryQualityService

from .common import _bootstrap, _quality_suggested_actions, _print_tree


def register(app: typer.Typer) -> None:
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
