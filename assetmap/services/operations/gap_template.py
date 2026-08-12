from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sqlmodel import Session

from assetmap.config import AppConfig
from assetmap.models import ScanTask
from assetmap.services.delivery.exporter import ExportService
from assetmap.services.delivery.report import ReportService


@dataclass
class GapTemplateResult:
    path: Path
    units: int
    skipped_existing: bool = False


class GapTemplateService:
    def __init__(self, session: Session, config: AppConfig) -> None:
        self.session = session
        self.config = config

    def write(
        self,
        task_id: int,
        output: Path | str,
        *,
        include_partial: bool = False,
        priority_filter: str = "all",
        force: bool = False,
    ) -> GapTemplateResult:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        path = Path(output)
        if path.exists() and not force:
            return GapTemplateResult(path=path, units=0, skipped_existing=True)
        rows = self._gap_rows(task_id, include_partial=include_partial, priority_filter=priority_filter)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            self._render(task, rows, include_partial=include_partial, priority_filter=priority_filter),
            encoding="utf-8",
        )
        return GapTemplateResult(path=path, units=len(rows))

    def _gap_rows(self, task_id: int, *, include_partial: bool, priority_filter: str = "all") -> list[dict]:
        bundle = ExportService(self.session)._bundle(task_id)
        context = ReportService(self.session, self.config)._context(bundle)
        rows = context["unit_coverage_rows"]
        allowed_priorities = self._priority_filter(priority_filter)
        wanted = []
        for row in rows:
            status = row.get("覆盖状态")
            if status == "人工确认无独立互联网资产":
                continue
            partial_in_scope = include_partial and status == "有资产线索，待扩大探测"
            if allowed_priorities is not None and row.get("复核优先级") not in allowed_priorities and not partial_in_scope:
                continue
            if status == "无资产线索" or (include_partial and status != "已覆盖互联网暴露面"):
                wanted.append(row)
        priority_order = {"高": 0, "中": 1, "低": 2, "无": 3, "": 4}
        status_order = {"无资产线索": 0, "有资产线索，待扩大探测": 1}
        return sorted(
            wanted,
            key=lambda row: (
                priority_order.get(row.get("复核优先级") or "", 4),
                status_order.get(row.get("覆盖状态") or "", 9),
                row.get("股权层级") if isinstance(row.get("股权层级"), int) else 99,
                row.get("单位") or "",
            ),
        )

    def _priority_filter(self, value: str) -> set[str] | None:
        normalized = (value or "all").strip().lower().replace("_", "-")
        if normalized in {"all", "*", "全部"}:
            return None
        if normalized in {"high-medium", "high,medium", "高,中", "高中", "priority"}:
            return {"高", "中"}
        if normalized in {"high", "高"}:
            return {"高"}
        if normalized in {"medium", "中"}:
            return {"中"}
        if normalized in {"low", "低"}:
            return {"低"}
        raise ValueError("Unsupported priority filter. Use all/high-medium/high/medium/low.")

    def _render(self, task: ScanTask, rows: list[dict], *, include_partial: bool, priority_filter: str) -> str:
        scope = "无资产线索及部分覆盖单位" if include_partial else "无资产线索单位"
        lines = [
            "# 资产缺口补充模板",
            f"# 任务: {task.id} {task.target}",
            f"# 范围: {scope}",
            f"# 优先级过滤: {priority_filter}",
            "# 填写后执行:",
            f"#   assetmap import-assets {task.id} --file <本文件>",
            f"#   assetmap run {task.id} --manual-file <本文件>",
            f"#   或直接执行: assetmap import-assets {task.id} --file <本文件> --continue",
            "#",
            "# 每个单位下面可以填写 domains/subdomains/ips/urls/apps/mini_programs/",
            "# wechat_official_accounts/wechat_service_accounts/emails。",
            "# 支持中文同义字段，例如 备案网站/公网IP/APP备案/微信小程序备案/微信公众号备案/微信服务号备案/邮箱地址。",
            "# source_urls 用于记录人工核验来源，review_status/notes 用于复核留痕；这些字段不会当作资产导入。",
            "# search_keywords 是建议检索词，便于复核人员到备案、官网、公众号、应用商店、搜索引擎等来源核验；不会当作资产导入。",
            "# 建议每个高/中优先级单位至少填入 domains/urls/ips/apps/mini_programs/wechat/emails 中的一类资产。",
            "# 如果人工确认该单位确实没有独立互联网资产，请保留空资产列表，将 review_status 改为 no_assets_found，并在 notes/source_urls 中说明核验依据。",
            "# 示例：",
            "#   domains:",
            "#     - example.cn",
            "#   urls:",
            "#     - url: https://portal.example.cn/",
            "#       system_name: 示例门户",
            "#       site_purpose: 统一登录入口",
            "#   ips:",
            "#     - ip: 1.2.3.4",
            "#       source: 防火墙台账",
            "#   apps:",
            "#     - name: 示例 APP",
            "#       package: cn.example.app",
            "#   source_urls:",
            "#     - https://beian.miit.gov.cn/",
            "",
            "units:",
        ]
        if not rows:
            lines.extend(["  []", ""])
            return "\n".join(lines)
        for row in rows:
            lines.extend(
                [
                    f"  - unit: {_yaml_string(row.get('单位') or '')}",
                    (
                        "    # 股权范围: "
                        f"层级={row.get('股权层级', '')}, 直接持股={row.get('直接持股', '')}, "
                        f"累计持股={row.get('累计持股', '')}, 子公司={row.get('子公司数量', 0)}"
                    ),
                    f"    # 股权路径: {row.get('股权路径') or row.get('单位') or ''}",
                    f"    # 当前覆盖状态: {row.get('覆盖状态') or ''}",
                    f"    # 复核优先级: {row.get('复核优先级') or ''}",
                    f"    # 缺口原因: {row.get('缺口原因') or ''}",
                    (
                        "    # 当前统计: "
                        f"资产={row.get('资产数量', 0)}, 根域名={row.get('根域名数量', 0)}, "
                        f"DNS主机={row.get('子域名/DNS主机数量', 0)}, IP={row.get('IP数量', 0)}, "
                        f"开放端口={row.get('开放端口数量', 0)}, Web入口={row.get('Web入口数量', 0)}"
                    ),
                    "    domains: []",
                    "    subdomains: []",
                    "    ips: []",
                    "    urls: []",
                    "    apps: []",
                    "    mini_programs: []",
                    "    wechat_official_accounts: []",
                    "    wechat_service_accounts: []",
                    "    emails: []",
                    "    minimum_required: \"至少填写一类资产；若确认无资产，将 review_status 改为 no_assets_found 并写明依据\"",
                    "    search_keywords:",
                    f"      - {_yaml_string((row.get('单位') or '') + ' 官网')}",
                    f"      - {_yaml_string((row.get('单位') or '') + ' 备案')}",
                    f"      - {_yaml_string((row.get('单位') or '') + ' 小程序')}",
                    f"      - {_yaml_string((row.get('单位') or '') + ' 公众号')}",
                    f"      - {_yaml_string((row.get('单位') or '') + ' APP')}",
                    f"      - {_yaml_string((row.get('单位') or '') + ' 邮箱')}",
                    "    review_checklist:",
                    "      - source: 工信部ICP备案",
                    "        status: pending",
                    "        notes: \"\"",
                    "      - source: 官网/搜索引擎",
                    "        status: pending",
                    "        notes: \"\"",
                    "      - source: 微信公众号/小程序",
                    "        status: pending",
                    "        notes: \"\"",
                    "      - source: 应用商店/APP备案",
                    "        status: pending",
                    "        notes: \"\"",
                    "      - source: 内部台账/防火墙/邮箱",
                    "        status: pending",
                    "        notes: \"\"",
                    "    source_urls: []",
                    "    review_status: pending",
                    "    notes: \"\"",
                    "",
                ]
            )
        return "\n".join(lines)


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
