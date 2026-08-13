"""Standalone entry point for the port-discovery stage.

Examples:
    python -m assetmap.stages.port_discovery --task-id 12
    python -m assetmap.stages.port_discovery --task-id 12 --rerun
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.mapping.nmap_scan import NmapScanService


def run(
    config: AppConfig,
    *,
    task_id: int,
    rerun: bool = False,
    progress: Callable[[str], None] = print,
) -> int:
    """Run the production port-discovery service as a single stage."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return NmapScanService(session, config, progress=progress).run(task_id, rerun=rerun)
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行端口发现阶段。")
    parser.add_argument("--task-id", type=int, required=True, help="已有扫描任务 ID。")
    parser.add_argument("--rerun", action="store_true", help="明确重新执行端口发现阶段中已完成的小任务。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result_id = run(load_config(args.config), task_id=args.task_id, rerun=args.rerun)
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；已保存的检查点可用于后续继续。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[port-discovery] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[port-discovery] 完成：子任务 ID={result_id}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
