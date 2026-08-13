"""Standalone entry point for the domain-mapping stage.

Example: ``python -m assetmap.stages.domain_mapping --task-id 1``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from assetmap.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from assetmap.db import create_db_and_engine, get_session
from assetmap.services.mapping.subdomain import SubdomainService


def run(
    config: AppConfig,
    *,
    task_id: int,
    rerun_tools: bool = False,
    rerun_dns: bool = False,
    skip_ai: bool = False,
    progress: Callable[[str], None] = print,
) -> int:
    """Run the production domain-mapping service for one existing scan task."""
    engine = create_db_and_engine(config.database_url)
    session = get_session(engine)
    try:
        return SubdomainService(session, config, progress=progress).run(
            task_id,
            run_ai=not skip_ai,
            rerun_tools=rerun_tools,
            rerun_dns=rerun_dns,
        )
    finally:
        session.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立执行域名测绘与严格源站筛选阶段。")
    parser.add_argument("--task-id", type=int, required=True, help="已有资产任务 ID。")
    parser.add_argument("--rerun-tools", action="store_true", help="重跑 subfinder 与 dnsx。")
    parser.add_argument("--rerun-dns", action="store_true", help="清除并重做 DNS 解析。")
    parser.add_argument("--skip-ai", action="store_true", help="诊断用途：不调用 AI，自动候选将全部排除。")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="配置文件路径。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        stage_id = run(
            config,
            task_id=args.task_id,
            rerun_tools=args.rerun_tools,
            rerun_dns=args.rerun_dns,
            skip_ai=args.skip_ai,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] 已中断；可再次执行相同命令继续。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[domain-mapping] 失败：{exc}", file=sys.stderr)
        return 1
    print(f"[domain-mapping] 完成：子任务 ID={stage_id}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
