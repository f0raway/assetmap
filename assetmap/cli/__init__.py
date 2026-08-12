"""CLI 命令包"""

import typer

from .config import register as register_config
from .pipeline import register as register_pipeline
from .report import register as register_report
from .assets import register as register_assets
from .review import register as register_review
from .show import register as register_show

from .common import PIPELINE_STAGES, _stage_status_map, _warn_environment, _should_run_stage, _quality_suggested_actions, manual_import_next_command
from .pipeline import _run_pipeline, _prompt_manual_asset_import, _run_one_click_scan
from .review import _execute_improve_actions, _coalesce_improve_actions, _select_improve_actions

app = typer.Typer(help="互联网数字资产暴露面测绘系统 v1")

# 注册所有命令模块
register_config(app)
register_pipeline(app)
register_report(app)
register_assets(app)
register_review(app)
register_show(app)


__all__ = ["app"]
