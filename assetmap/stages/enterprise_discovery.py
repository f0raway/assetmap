"""Standalone entry point for the enterprise-discovery stage.

Examples:
    python -m assetmap.stages.enterprise_discovery --target "某公司"
    python -m assetmap.stages.enterprise_discovery --task-id 12
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.acquisition.discovery import DiscoveryResult, DiscoveryService


def run(
    config: AppConfig,
    *,
    target: str | None = None,
    task_id: int | None = None,
    fresh: bool = False,
    progress: Callable[[str], None] = print,
) -> DiscoveryResult:
    """Run the production enterprise-discovery service as a single stage."""
    if not target and task_id is None:
        raise ValueError("请提供 --target 或 --task-id。")
    if target and task_id is not None:
        raise ValueError("--target 与 --task-id 不能同时使用。")
    if fresh and task_id is not None:
        raise ValueError("--fresh 仅能与 --target 一起使用。")

    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return DiscoveryService(session, config, progress=progress).run(
            target,
            resume_task_id=task_id,
            fresh=fresh,
        )
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行企业发现阶段。")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--target", help="目标公司名称。")
    target.add_argument("--task-id", type=int, help="续跑已有任务 ID。")
    parser.add_argument("--fresh", action="store_true", help="忽略同名任务并重新采集。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.fresh and args.task_id is not None:
        build_arg_parser().error("--fresh 仅能与 --target 一起使用。")
    try:
        config = load_config(args.config)
        result = run(
            config,
            target=args.target,
            task_id=args.task_id,
            fresh=args.fresh,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；已保存的检查点可用于后续继续。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[enterprise-discovery] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[enterprise-discovery] 完成：task_id={result.task_id}，企业={result.company_count}，资产={result.asset_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
