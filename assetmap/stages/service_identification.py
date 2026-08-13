"""Standalone entry point for service identification and Web probing.

Example: ``python -m assetmap.stages.service_identification --task-id 1``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.identification.asset_classifier import AssetClassifierService


def run(
    config: AppConfig,
    *,
    task_id: int,
    rerun: bool = False,
    progress: Callable[[str], None] = print,
) -> int:
    """Run the production service-identification stage for an existing task."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return AssetClassifierService(session, config, progress=progress).run(task_id, rerun=rerun)
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行服务识别与 Web 入口发现阶段。")
    parser.add_argument("--task-id", type=int, required=True, help="已有资产任务 ID。")
    parser.add_argument("--rerun", action="store_true", help="清除并重新探测已有服务识别结果。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        stage_id = run(load_config(args.config), task_id=args.task_id, rerun=args.rerun)
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；未完成的入口可在下次运行继续处理。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[service-identification] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[service-identification] 完成：子任务 ID={stage_id}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
