"""Standalone entry point for the Web page identification stage.

Examples:
    python -m assetmap.stages.web_identification --task-id 12
    python -m assetmap.stages.web_identification --task-id 12 --retry-failed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.identification.url_discovery import UrlDiscoveryService


def run(
    config: AppConfig,
    *,
    task_id: int,
    rerun: bool = False,
    retry_failed: bool = False,
    progress: Callable[[str], None] = print,
) -> int:
    """Run URL seeding, rendered-HTML capture, and text AI identification only."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return UrlDiscoveryService(session, config, progress=progress).run(
            task_id,
            rerun=rerun,
            retry_failed=retry_failed,
        )
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行 Web 页面发现与智能识别阶段。")
    parser.add_argument("--task-id", type=int, required=True, help="已有扫描任务 ID。")
    parser.add_argument("--rerun", action="store_true", help="明确重新执行全部已保存的页面识别。")
    parser.add_argument("--retry-failed", action="store_true", help="仅重新尝试页面渲染或 AI 识别失败的页面。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result_id = run(
            load_config(args.config),
            task_id=args.task_id,
            rerun=args.rerun,
            retry_failed=args.retry_failed,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；已完成的页面识别结果会在下次运行时跳过。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[web-identification] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[web-identification] 完成：子任务 ID={result_id}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
