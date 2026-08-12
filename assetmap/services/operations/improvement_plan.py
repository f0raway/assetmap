from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import Session

from assetmap.config import AppConfig
from assetmap.models import ScanTask
from assetmap.services.delivery.exporter import ExportService
from assetmap.services.delivery.quality import DeliveryQualityService
from assetmap.services.delivery.report import ReportService


@dataclass
class ImprovementPlanResult:
    json_path: Path
    text_path: Path
    quality_status: str
    action_count: int
    automatic_actions: int
    manual_actions: int


class ImprovementPlanService:
    def __init__(self, session: Session, config: AppConfig) -> None:
        self.session = session
        self.config = config

    def write(
        self,
        task_id: int,
        output_dir: Path | str = Path("data") / "improvement",
        *,
        reports_dir: Path | str = "reports",
    ) -> ImprovementPlanResult:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)

        payload = self._payload(task, reports_dir=reports_dir)
        json_path = output / f"task_{task.id}_improvement_plan.json"
        text_path = output / f"task_{task.id}_improvement_plan.txt"
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        text_path.write_text(self._render_text(payload), encoding="utf-8")

        actions = payload["actions"]
        return ImprovementPlanResult(
            json_path=json_path,
            text_path=text_path,
            quality_status=payload["quality"]["status"],
            action_count=len(actions),
            automatic_actions=sum(1 for item in actions if item["mode"] == "automatic"),
            manual_actions=sum(1 for item in actions if item["mode"] == "manual"),
        )

    def _payload(self, task: ScanTask, *, reports_dir: Path | str) -> dict[str, Any]:
        quality = DeliveryQualityService(self.session, self.config).check(task.id, output_dir=reports_dir)
        bundle = ExportService(self.session)._bundle(task.id)
        context = ReportService(self.session, self.config)._context(bundle)
        coverage_rows = context["coverage_rows"]
        actions = self._actions(task, quality, context)
        return {
            "task": {"id": task.id, "target": task.target},
            "purpose": "下一轮补全计划：把质量门禁、覆盖缺口和复核清单转换为可执行动作。",
            "quality": {
                "status": quality.status,
                "failures": quality.failures,
                "warnings": quality.warnings,
            },
            "metrics": {
                "companies": context["stats"].get("单位数量", 0),
                "assets": context["stats"].get("资产数量", 0),
                "open_ports": context["stats"].get("开放端口数量", 0),
                "web_entrypoints": context["stats"].get("Web入口数量", 0),
                "web_visual_coverage": context["stats"].get("Web识别覆盖率", ""),
                "coverage_gap_items": sum(1 for row in coverage_rows if row.get("缺口等级") not in {"", "无"}),
                "dns_review_items": self._review_count(context["dns_quality_rows"]),
                "service_review_items": self._review_count(context["service_audit_rows"]),
                "url_review_items": self._review_count(context["url_coverage_rows"]),
                "visual_review_items": self._review_count(context["visual_review_rows"]),
            },
            "coverage_gates": coverage_rows,
            "actions": actions,
            "suggested_order": [item["id"] for item in actions],
        }

    def _actions(self, task: ScanTask, quality, context: dict[str, Any]) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        sequence = 1
        for failure in quality.failures:
            actions.append(
                self._action(
                    sequence,
                    "流程补齐",
                    "automatic",
                    "high",
                    failure,
                    f"assetmap run {task.id}",
                    "流程存在失败或未完成阶段，先让总控命令补齐流水线。",
                )
            )
            sequence += 1

        coverage_rows = [row for row in context["coverage_rows"] if row.get("缺口等级") not in {"", "无"}]
        no_asset_units = [row for row in context["unit_coverage_rows"] if row.get("覆盖状态") == "无资产线索"]
        priority_asset_units = [
            row for row in no_asset_units if row.get("复核优先级") in {"高", "中"}
        ]
        partial_units = [
            row
            for row in context["unit_coverage_rows"]
            if row.get("覆盖状态") not in {"无资产线索", "已覆盖互联网暴露面"}
        ]
        dns_review = [row for row in context["dns_quality_rows"] if row.get("复核优先级") not in {"", "无"}]
        service_review = [row for row in context["service_audit_rows"] if row.get("复核优先级") not in {"", "无"}]
        url_review = [row for row in context["url_coverage_rows"] if row.get("复核优先级") not in {"", "无"}]
        visual_review = [row for row in context["visual_review_rows"] if row.get("复核优先级") not in {"", "无"}]
        visual_retry_needed = self._visual_retry_needed(visual_review)
        dns_rerun_needed = self._dns_rerun_needed(coverage_rows, dns_review)
        port_active_validation_needed = self._port_active_validation_needed(coverage_rows)
        service_rerun_needed = self._service_rerun_needed(coverage_rows, service_review, url_review)

        if self._has_gap(coverage_rows, "企业/备案资产"):
            actions.append(
                self._action(
                    sequence,
                    "企业/备案资产",
                    "manual",
                    "high" if any(row.get("复核优先级") == "高" for row in priority_asset_units) else ("medium" if priority_asset_units else "low"),
                    (
                        f"{len(no_asset_units)} 家单位无资产线索，其中高/中优先级 {len(priority_asset_units)} 家；"
                        f"{len(partial_units)} 家单位只有部分覆盖。"
                    ),
                    f"assetmap asset-gap-template {task.id} --priority high-medium --output data/manual_assets.task_{task.id}.gaps.yaml --include-partial --force",
                    "生成待补充模板后，优先补齐高/中优先级单位，再补项目公司；补充官网、根域名、子域名、IP、URL、APP、小程序、公众号、服务号和邮箱。",
                    samples=self._unique_samples(self._unit_sample(row) for row in [*priority_asset_units, *partial_units, *no_asset_units])[:10],
                    follow_up=f"assetmap run {task.id} --manual-file data/manual_assets.task_{task.id}.gaps.yaml",
                )
            )
            sequence += 1

        if self._has_gap(coverage_rows, "子域名/DNS"):
            actions.append(
                self._action(
                    sequence,
                    "子域名/DNS",
                    "automatic" if dns_rerun_needed else "manual",
                    "medium" if dns_review else "low",
                    f"{len(dns_review)} 个根域名或 DNS 证据需要复核。",
                    f"assetmap run {task.id} --from-stage subdomains --rerun-subdomain-tools"
                    if dns_rerun_needed
                    else f"assetmap review-workorder {task.id} --output data/review_workorder.task_{task.id}.yaml --force",
                    "重跑被动枚举和主动爆破，并刷新 DNS、端口、服务、URL 和报告。"
                    if dns_rerun_needed
                    else "不重跑 DNS 工具，先按复核工作单确认无公网解析、第三方 CNAME、共享 IP 或停放域名；填写 review_status 后导入复核结论。",
                    samples=[row.get("根域名") for row in dns_review[:10]],
                    follow_up=None if dns_rerun_needed else f"assetmap import-review {task.id} --file data/review_workorder.task_{task.id}.yaml",
                )
            )
            sequence += 1

        if self._has_gap(coverage_rows, "端口发现"):
            actions.append(
                self._action(
                    sequence,
                    "端口发现",
                    "automatic",
                    "medium" if port_active_validation_needed else "high",
                    "开放端口存在 FOFA-only 被动证据，建议主动验证后形成交叉证据。"
                    if port_active_validation_needed
                    else "存在候选公网 IP 缺少端口发现证据。",
                    f"assetmap nmap-scan {task.id} --sources nmap,fofa --rerun"
                    if port_active_validation_needed
                    else f"assetmap run {task.id} --from-stage port-scan --rerun-ports",
                    "对 FOFA-only 端口执行一次精确主动 nmap 验证，并与被动证据合并。"
                    if port_active_validation_needed
                    else "汇总 DNS AI 真实 IP、手工 IP 和 DNS 公网解析后，重跑 nmap/FOFA 端口发现。",
                )
            )
            sequence += 1

        if self._has_gap(coverage_rows, "服务识别/URL"):
            actions.append(
                self._action(
                    sequence,
                    "服务识别/URL",
                    "automatic" if service_rerun_needed else "manual",
                    "medium" if service_rerun_needed else "low",
                    f"{len(service_review)} 个服务、{len(url_review)} 个 URL 入口需要复核。",
                    f"assetmap run {task.id} --from-stage classify --rerun-classify"
                    if service_rerun_needed
                    else f"assetmap review-workorder {task.id} --output data/review_workorder.task_{task.id}.yaml --force",
                    "重新做服务指纹、Web 探测和 URL 入口关联，必要时结合复核工作单补充 Host/URL。"
                    if service_rerun_needed
                    else "不重跑服务识别，先按复核工作单人工确认 passive_fofa、疑似 Web 和未知服务证据；填写 review_status 后导入复核结论。",
                    samples=[item for item in self._endpoint_samples(service_review, url_review)[:10]],
                    follow_up=None if service_rerun_needed else f"assetmap import-review {task.id} --file data/review_workorder.task_{task.id}.yaml",
                )
            )
            sequence += 1

        if self._has_gap(coverage_rows, "URL视觉识别"):
            actions.append(
                self._action(
                    sequence,
                    "URL视觉识别",
                    "automatic" if visual_retry_needed else "manual",
                    "medium" if visual_retry_needed else "low",
                    f"{len(visual_review)} 个 Web 入口需要视觉复核或曾使用降级识别。",
                    f"assetmap url-discover {task.id} --retry-failed" if visual_retry_needed else f"assetmap review-workorder {task.id} --output data/review_workorder.task_{task.id}.yaml --force",
                    "只重试失败或缺失视觉识别的页面；对 HTTP 降级页面保留复核清单。"
                    if visual_retry_needed
                    else "不重跑截图流程，直接按复核工作单人工核对低置信度、低价值错误/拦截页、降级识别和编码异常页面；填写 review_status 后导入复核结论。",
                    samples=[row.get("URL") for row in visual_review[:10]],
                    follow_up=None if visual_retry_needed else f"assetmap import-review {task.id} --file data/review_workorder.task_{task.id}.yaml",
                )
            )
            sequence += 1

        if actions:
            actions.append(
                self._action(
                    sequence,
                    "报告交付",
                    "automatic",
                    "medium",
                    "完成补全动作后重新收口交付物。",
                    f"assetmap deliver {task.id}",
                    "重新生成 Word、Excel、质量门禁、交付包和 manifest 校验。",
                )
            )
        return actions

    def _action(
        self,
        sequence: int,
        phase: str,
        mode: str,
        priority: str,
        reason: str,
        command: str,
        expected_effect: str,
        *,
        samples: list[Any] | None = None,
        follow_up: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "id": f"A{sequence:02d}",
            "phase": phase,
            "mode": mode,
            "priority": priority,
            "reason": reason,
            "command": command,
            "expected_effect": expected_effect,
            "samples": [item for item in (samples or []) if item],
        }
        if follow_up:
            payload["follow_up_command"] = follow_up
        return payload

    def _render_text(self, payload: dict[str, Any]) -> str:
        task = payload["task"]
        quality = payload["quality"]
        metrics = payload["metrics"]
        lines = [
            "互联网数字资产暴露面下一轮补全计划",
            "",
            f"任务编号：{task['id']}",
            f"测绘对象：{task['target']}",
            f"质量状态：{quality['status']}",
            "",
            "关键指标：",
            f"- 单位数量：{metrics['companies']}",
            f"- 资产数量：{metrics['assets']}",
            f"- 开放端口：{metrics['open_ports']}",
            f"- Web入口：{metrics['web_entrypoints']}",
            f"- 视觉识别覆盖：{metrics['web_visual_coverage']}",
            f"- 覆盖缺口项：{metrics['coverage_gap_items']}",
            "",
            "建议动作：",
        ]
        if not payload["actions"]:
            lines.append("- 当前没有需要补全的动作。")
        for action in payload["actions"]:
            lines.extend(
                [
                    f"- {action['id']} [{action['priority']}/{action['mode']}] {action['phase']}",
                    f"  原因：{action['reason']}",
                    f"  命令：{action['command']}",
                    f"  预期：{action['expected_effect']}",
                ]
            )
            if action.get("follow_up_command"):
                lines.append(f"  后续：{action['follow_up_command']}")
            if action.get("samples"):
                lines.append("  样例：" + "，".join(str(item) for item in action["samples"][:10]))
        if quality["warnings"]:
            lines.extend(["", "质量警告："])
            lines.extend(f"- {item}" for item in quality["warnings"])
        if quality["failures"]:
            lines.extend(["", "质量失败："])
            lines.extend(f"- {item}" for item in quality["failures"])
        return "\n".join(lines) + "\n"

    def _has_gap(self, rows: list[dict[str, Any]], phase: str) -> bool:
        return any(row.get("环节") == phase for row in rows)

    def _visual_retry_needed(self, rows: list[dict[str, Any]]) -> bool:
        return any(row.get("分析错误") or not row.get("识别方式") for row in rows)

    def _dns_rerun_needed(self, coverage_rows: list[dict[str, Any]], dns_review: list[dict[str, Any]]) -> bool:
        if any(
            row.get("环节") == "子域名/DNS"
            and row.get("指标") in {"根域名解析覆盖", "子域名枚举质量"}
            for row in coverage_rows
        ):
            return True
        return any("tool_failure" in str(row.get("复核类型") or "") for row in dns_review)

    def _port_active_validation_needed(self, coverage_rows: list[dict[str, Any]]) -> bool:
        return any(
            row.get("环节") == "端口发现"
            and row.get("指标") == "端口证据来源质量"
            for row in coverage_rows
        )

    def _service_rerun_needed(
        self,
        coverage_rows: list[dict[str, Any]],
        service_review: list[dict[str, Any]],
        url_review: list[dict[str, Any]],
    ) -> bool:
        if url_review:
            return True
        if any(
            row.get("环节") == "服务识别/URL"
            and row.get("指标") in {"Web 服务入口覆盖", "URL 入口关联质量"}
            for row in coverage_rows
        ):
            return True
        rerunnable_types = {"missing_url_entry", "web_like_non_web", "unknown_service"}
        return any(row.get("复核类型") in rerunnable_types for row in service_review)

    def _review_count(self, rows: list[dict[str, Any]]) -> int:
        return sum(1 for row in rows if row.get("复核优先级") not in {"", "无"})

    def _endpoint_samples(self, service_review: list[dict[str, Any]], url_review: list[dict[str, Any]]) -> list[str]:
        samples = [f"{row.get('IP')}:{row.get('端口')}" for row in service_review]
        samples.extend(row.get("URL入口样例") or f"{row.get('IP')}:{row.get('端口')}" for row in url_review)
        return samples

    def _unit_sample(self, row: dict[str, Any]) -> str:
        return f"{row.get('单位')}[{row.get('复核优先级') or '未分级'}]"

    def _unique_samples(self, values) -> list[str]:
        output = []
        for value in values:
            if value and value not in output:
                output.append(value)
        return output
