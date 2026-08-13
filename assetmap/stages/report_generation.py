"""Standalone entry point for the report-generation stage.

Examples:
    python -m assetmap.stages.report_generation --task-id 12
    python -m assetmap.stages.report_generation --task-id 12 --rerun-ai
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.delivery.report import ReportResult, ReportService


def run(
    config: AppConfig,
    *,
    task_id: int,
    output_dir: Path | str = "reports",
    rerun_ai: bool = False,
    progress: Callable[[str], None] = print,
) -> ReportResult:
    """Generate Word/Excel report artifacts for one existing task."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return ReportService(session, config, progress=progress).run(
            task_id,
            output_dir=output_dir,
            rerun_ai=rerun_ai,
        )
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行报告生成阶段。")
    parser.add_argument("--task-id", type=int, required=True, help="已有扫描任务 ID。")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="报告输出目录。")
    parser.add_argument("--rerun-ai", action="store_true", help="强制重新执行四个报告 AI 分块。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result = run(
            load_config(args.config),
            task_id=args.task_id,
            output_dir=args.output_dir,
            rerun_ai=args.rerun_ai,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；已完成的 AI 分块会在下次运行时复用。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[report-generation] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[report-generation] 完成：{result.report_path}")
    print(f"[report-generation] 附件：{result.asset_workbook_path}")
    print(f"[report-generation] Web 附件：{result.web_workbook_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
