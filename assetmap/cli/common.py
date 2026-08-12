"""CLI 公共工具和辅助函数"""

from __future__ import annotations

from pathlib import Path

import typer
from sqlmodel import select

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import Company, CompanyAssetLink, CompanyEdge, InternetAsset, ScanTask, WebEntrypoint
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.runtime.tool_resolver import ToolResolver


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


def _command_path(path: Path | str) -> str:
    text = str(path)
    if any(char.isspace() for char in text):
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'
    return text


def manual_import_next_command(task_id: int, file: Path | str) -> str:
    return f"assetmap run {task_id} --manual-file {_command_path(file)}"


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
    rows = session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == task_id)).all()
    for row in rows:
        visual = (row.evidence or {}).get("visual_analysis")
        if not isinstance(visual, dict):
            return True
        if visual.get("analysis_method") == "http_probe_fallback":
            return True
    return False


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
