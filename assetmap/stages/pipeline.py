"""Unified orchestration for the independently runnable assetmap stages.

The pipeline calls the public ``run`` function of each stage module instead of
calling their underlying services directly.  This keeps standalone debugging
and one-click execution on exactly the same production path.

Examples:
    python -m assetmap.stages.pipeline --target "某集团有限公司"
    python -m assetmap.stages.pipeline --task-id 12
    python -m assetmap.stages.pipeline --task-id 12 --from-stage port-discovery
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from sqlmodel import select

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import WebEntrypoint
from assetmap.services.acquisition.manual_import import ManualAssetImportService
from assetmap.services.operations.status import PipelineStatusService

from . import (
    domain_mapping,
    enterprise_discovery,
    port_discovery,
    report_generation,
    service_identification,
    web_identification,
)


STAGES = (
    "enterprise-discovery",
    "domain-mapping",
    "port-discovery",
    "service-identification",
    "web-identification",
    "report-generation",
)
STATUS_STAGE = {
    "enterprise-discovery": "discover",
    "domain-mapping": "subdomains",
    "port-discovery": "port-scan",
    "service-identification": "classify",
    "web-identification": "url-discover",
    "report-generation": "report",
}
STAGE_ALIASES = {
    "discover": "enterprise-discovery",
    "enterprise": "enterprise-discovery",
    "subdomains": "domain-mapping",
    "domain": "domain-mapping",
    "port-scan": "port-discovery",
    "nmap": "port-discovery",
    "classify": "service-identification",
    "service": "service-identification",
    "url-discover": "web-identification",
    "url": "web-identification",
    "web": "web-identification",
    "report": "report-generation",
}


@dataclass(frozen=True)
class PipelineResult:
    task_id: int
    executed: tuple[str, ...]
    skipped: tuple[str, ...]


def _normal_stage(value: str) -> str:
    stage = STAGE_ALIASES.get(value.lower().strip(), value.lower().strip())
    if stage not in STAGES:
        allowed = ", ".join(STAGES)
        raise ValueError(f"不支持的阶段：{value}。可选：{allowed}")
    return stage


def _selected_stages(from_stage: str, to_stage: str) -> tuple[str, ...]:
    start = _normal_stage(from_stage)
    end = _normal_stage(to_stage)
    start_index = STAGES.index(start)
    end_index = STAGES.index(end)
    if start_index > end_index:
        raise ValueError("--from-stage 必须位于 --to-stage 之前。")
    return STAGES[start_index : end_index + 1]


def _stage_statuses(config: AppConfig, task_id: int) -> dict[str, str]:
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        status = PipelineStatusService(session).get(task_id)
        return {name: value for name, value, _detail in status.stages}
    finally:
        session.close()


def _has_incomplete_page_identification(config: AppConfig, task_id: int) -> bool:
    """Do not turn completed HTTP fallbacks into automatic slow retries."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        for row in session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == task_id)).all():
            evidence = row.evidence or {}
            visual = evidence.get("visual_analysis")
            if not isinstance(visual, dict):
                return True
            if visual.get("analysis_method") == "screenshot_ai" or evidence.get("visual_analysis_error"):
                return True
        return False
    finally:
        session.close()


def _should_run(statuses: dict[str, str], stage: str, *, force: bool) -> bool:
    return force or statuses.get(STATUS_STAGE[stage]) not in {"completed", "skipped", "completed_with_gaps"}


def _import_manual_assets(config: AppConfig, task_id: int, path: Path, progress: Callable[[str], None]) -> None:
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        ManualAssetImportService(session, progress=progress).run(task_id, path)
    finally:
        session.close()


def run(
    config: AppConfig,
    *,
    target: str | None = None,
    task_id: int | None = None,
    fresh: bool = False,
    manual_file: Path | None = None,
    from_stage: str = "enterprise-discovery",
    to_stage: str = "report-generation",
    rerun: bool = False,
    rerun_tools: bool = False,
    rerun_dns: bool = False,
    rerun_ports: bool = False,
    rerun_classify: bool = False,
    rerun_urls: bool = False,
    rerun_ai: bool = False,
    skip_ai: bool = False,
    retry_failed: bool = False,
    force_changed: bool = False,
    output_dir: Path | str = "reports",
    progress: Callable[[str], None] = print,
) -> PipelineResult:
    """Run selected stages in dependency order with stage-level resume rules."""
    if bool(target) == bool(task_id is not None):
        raise ValueError("请二选一提供 target 或 task_id。")
    selected = _selected_stages(from_stage, to_stage)
    if target and selected[0] != "enterprise-discovery":
        raise ValueError("使用 target 新建任务时，--from-stage 必须为 enterprise-discovery。")
    if fresh and not target:
        raise ValueError("--fresh 只能与 target 一起使用。")

    executed: list[str] = []
    skipped: list[str] = []
    # The CLI uses this after manual import/TUI updates.  Do not infer a
    # change merely because an existing task's discovery stage was resumed:
    # that would unnecessarily repeat every expensive downstream stage.
    changed = force_changed

    if target:
        progress(f"[pipeline] enterprise-discovery -> {target}")
        discovery = enterprise_discovery.run(config, target=target, fresh=fresh, progress=progress)
        task_id = discovery.task_id
        executed.append("enterprise-discovery")
        changed = changed or fresh
    assert task_id is not None
    progress(f"[pipeline] task={task_id}, stages={','.join(selected)}")

    if manual_file:
        progress(f"[pipeline] import manual assets -> {manual_file}")
        _import_manual_assets(config, task_id, manual_file, progress)
        changed = True

    if "enterprise-discovery" in selected and not target:
        statuses = _stage_statuses(config, task_id)
        if _should_run(statuses, "enterprise-discovery", force=rerun):
            progress("[pipeline] enterprise-discovery -> resume task")
            enterprise_discovery.run(config, task_id=task_id, progress=progress)
            executed.append("enterprise-discovery")
            changed = True
        else:
            progress("[pipeline] skip enterprise-discovery")
            skipped.append("enterprise-discovery")

    definitions = (
        (
            "domain-mapping",
            lambda: domain_mapping.run(
                config,
                task_id=task_id,
                rerun_tools=rerun or rerun_tools,
                rerun_dns=rerun or rerun_tools or rerun_dns,
                skip_ai=skip_ai,
                progress=progress,
            ),
            rerun or rerun_tools or rerun_dns,
        ),
        (
            "port-discovery",
            lambda: port_discovery.run(config, task_id=task_id, rerun=rerun or rerun_ports or changed, progress=progress),
            rerun or rerun_ports,
        ),
        (
            "service-identification",
            lambda: service_identification.run(config, task_id=task_id, rerun=rerun or rerun_classify or changed, progress=progress),
            rerun or rerun_classify,
        ),
        (
            "web-identification",
            lambda: web_identification.run(
                config,
                task_id=task_id,
                rerun=rerun or rerun_urls or changed,
                retry_failed=retry_failed and not (rerun or rerun_urls or changed),
                progress=progress,
            ),
            rerun or rerun_urls,
        ),
        (
            "report-generation",
            lambda: report_generation.run(
                config,
                task_id=task_id,
                output_dir=output_dir,
                rerun_ai=rerun or rerun_ai or changed,
                progress=progress,
            ),
            rerun or rerun_ai,
        ),
    )
    for stage, invoke, explicit_force in definitions:
        if stage not in selected:
            continue
        statuses = _stage_statuses(config, task_id)
        # A domain-mapping task with partial tool/DNS failures is intentionally
        # resumable in a normal run.  Other completed-with-gaps results are
        # retained until the operator explicitly requests a retry.
        resumable_domain_gap = (
            stage == "domain-mapping"
            and statuses.get(STATUS_STAGE[stage]) == "completed_with_gaps"
        )
        force = explicit_force or changed or resumable_domain_gap
        should_run = _should_run(statuses, stage, force=force)
        if stage == "web-identification" and not should_run and retry_failed:
            should_run = _has_incomplete_page_identification(config, task_id)
        if not should_run:
            progress(f"[pipeline] skip {stage}")
            skipped.append(stage)
            continue
        progress(f"[pipeline] {stage}")
        invoke()
        executed.append(stage)
        changed = True

    statuses = _stage_statuses(config, task_id)
    progress("[pipeline] completed: " + ", ".join(f"{name}={value}" for name, value in statuses.items()))
    return PipelineResult(task_id=task_id, executed=tuple(executed), skipped=tuple(skipped))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="按顺序编排企业发现、域名、端口、服务、Web 和报告独立模块。")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--target", help="新建或续跑的目标企业名称。")
    source.add_argument("--task-id", type=int, help="已有任务 ID。")
    parser.add_argument("--fresh", action="store_true", help="仅 target 模式：重新企业采集。")
    parser.add_argument("--manual-file", type=Path, help="导入人工补充资产后继续。")
    parser.add_argument("--from-stage", default="enterprise-discovery", help="开始阶段。")
    parser.add_argument("--to-stage", default="report-generation", help="结束阶段。")
    parser.add_argument("--rerun", action="store_true", help="重跑所选范围内的已完成阶段。")
    parser.add_argument("--rerun-tools", action="store_true", help="重跑子域名工具。")
    parser.add_argument("--rerun-dns", action="store_true", help="重跑 DNS 解析。")
    parser.add_argument("--rerun-ports", action="store_true", help="重跑端口发现。")
    parser.add_argument("--rerun-classify", action="store_true", help="重跑服务识别。")
    parser.add_argument("--rerun-urls", action="store_true", help="重跑 Web 页面识别。")
    parser.add_argument("--rerun-ai", action="store_true", help="重跑报告 AI 分析。")
    parser.add_argument("--skip-ai", action="store_true", help="域名阶段跳过 AI 源站判断。")
    parser.add_argument("--retry-failed", action="store_true", help="仅在页面识别实际失败时重试。")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="报告输出目录。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result = run(
            load_config(args.config),
            target=args.target,
            task_id=args.task_id,
            fresh=args.fresh,
            manual_file=args.manual_file,
            from_stage=args.from_stage,
            to_stage=args.to_stage,
            rerun=args.rerun,
            rerun_tools=args.rerun_tools,
            rerun_dns=args.rerun_dns,
            rerun_ports=args.rerun_ports,
            rerun_classify=args.rerun_classify,
            rerun_urls=args.rerun_urls,
            rerun_ai=args.rerun_ai,
            skip_ai=args.skip_ai,
            retry_failed=args.retry_failed,
            output_dir=args.output_dir,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；下次执行相同命令会从已保存检查点继续。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[pipeline] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[pipeline] 完成：task_id={result.task_id}，执行={','.join(result.executed) or '无'}，跳过={','.join(result.skipped) or '无'}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
