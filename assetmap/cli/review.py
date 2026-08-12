"""复核和改进相关命令"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.operations.review_workorder import ReviewWorkOrderService
from assetmap.services.operations.review_import import ReviewImportService
from assetmap.services.operations.improvement_plan import ImprovementPlanService
from assetmap.services.operations.gap_template import GapTemplateService
from assetmap.services.identification.url_discovery import UrlDiscoveryService
from assetmap.services.delivery.report import ReportService
from assetmap.services.delivery.package import DeliveryPackageService, DeliveryPackageVerifier

from .common import _bootstrap, _exit_interrupted, _csv_values


def register(app: typer.Typer) -> None:
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
    from .pipeline import _run_pipeline

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
