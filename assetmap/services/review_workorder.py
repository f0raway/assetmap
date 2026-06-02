from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sqlmodel import Session

from assetmap.config import AppConfig
from assetmap.models import ScanTask
from assetmap.services.exporter import ExportService
from assetmap.services.report import ReportService


@dataclass
class ReviewWorkOrderResult:
    path: Path
    total_items: int
    asset_items: int
    dns_items: int
    service_items: int
    url_items: int
    visual_items: int
    skipped_existing: bool = False


class ReviewWorkOrderService:
    def __init__(self, session: Session, config: AppConfig) -> None:
        self.session = session
        self.config = config

    def write(
        self,
        task_id: int,
        output: Path | str,
        *,
        force: bool = False,
    ) -> ReviewWorkOrderResult:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        path = Path(output)
        if path.exists() and not force:
            return ReviewWorkOrderResult(path=path, total_items=0, asset_items=0, dns_items=0, service_items=0, url_items=0, visual_items=0, skipped_existing=True)

        bundle = ExportService(self.session)._bundle(task_id)
        context = ReportService(self.session, self.config)._context(bundle)
        asset_items = self._asset_items(context["unit_coverage_rows"])
        dns_items = self._dns_items(context["dns_quality_rows"])
        service_items = self._service_items(context["service_audit_rows"])
        url_items = self._url_items(context["url_coverage_rows"])
        visual_items = self._visual_items(context["visual_review_rows"])
        next_commands = self._next_commands(
            task.id,
            context["coverage_rows"],
            asset_items=asset_items,
            dns_items=dns_items,
            service_items=service_items,
            url_items=url_items,
            visual_items=visual_items,
        )
        payload = {
            "task": {
                "id": task.id,
                "target": task.target,
            },
            "purpose": "交付后复核工作单：用于补充核验、人工确认和下一轮自动复测。",
            "next_commands": next_commands,
            "summary": {
                "asset_review_items": len(asset_items),
                "dns_review_items": len(dns_items),
                "service_review_items": len(service_items),
                "url_review_items": len(url_items),
                "visual_review_items": len(visual_items),
                "visual_automatic_retry_items": sum(1 for item in visual_items if item.get("review_type") == "automatic_retry"),
                "visual_manual_review_items": sum(1 for item in visual_items if item.get("review_type") != "automatic_retry"),
                "total_review_items": len(asset_items) + len(dns_items) + len(service_items) + len(url_items) + len(visual_items),
            },
            "review_items": {
                "asset_supplement": asset_items,
                "dns": dns_items,
                "service_classification": service_items,
                "url_entrypoint": url_items,
                "visual_identification": visual_items,
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "# 资产测绘复核工作单\n"
            "# 完成人工复核或补充资产后，按 next_commands 中的命令续跑流程。\n"
            + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=120),
            encoding="utf-8",
        )
        return ReviewWorkOrderResult(
            path=path,
            total_items=payload["summary"]["total_review_items"],
            asset_items=len(asset_items),
            dns_items=len(dns_items),
            service_items=len(service_items),
            url_items=len(url_items),
            visual_items=len(visual_items),
        )

    def _asset_items(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        review_rows = [
            row
            for row in rows
            if (
                row.get("复核优先级") in {"高", "中"}
                or row.get("覆盖状态") == "有资产线索，待扩大探测"
            )
            and row.get("覆盖状态") != "已覆盖互联网暴露面"
        ]
        priority_order = {"高": 0, "中": 1}
        return [
            {
                "priority": row.get("复核优先级"),
                "unit": row.get("单位"),
                "holding_depth": row.get("股权层级"),
                "direct_holding": row.get("直接持股"),
                "cumulative_holding": row.get("累计持股"),
                "child_company_count": row.get("子公司数量"),
                "coverage_status": row.get("覆盖状态"),
                "gap_reason": row.get("缺口原因"),
                "suggested_action": row.get("建议动作"),
                "ownership_path": row.get("股权路径"),
                "asset_fields_to_fill": [
                    "domains",
                    "subdomains",
                    "ips",
                    "urls",
                    "apps",
                    "mini_programs",
                    "wechat_official_accounts",
                    "wechat_service_accounts",
                    "emails",
                ],
                "search_keywords": [
                    f"{row.get('单位')} 官网",
                    f"{row.get('单位')} 备案",
                    f"{row.get('单位')} 小程序",
                    f"{row.get('单位')} 公众号",
                    f"{row.get('单位')} APP",
                ],
            }
            for row in sorted(review_rows, key=lambda item: (priority_order.get(item.get("复核优先级"), 9), item.get("股权层级") or 99, item.get("单位") or ""))
        ]

    def _next_commands(
        self,
        task_id: int,
        coverage_rows: list[dict[str, Any]],
        *,
        asset_items: list[dict[str, Any]],
        dns_items: list[dict[str, Any]],
        service_items: list[dict[str, Any]],
        url_items: list[dict[str, Any]],
        visual_items: list[dict[str, Any]],
    ) -> list[str]:
        commands: list[str] = []
        if asset_items:
            commands.extend(
                [
                    f"assetmap asset-gap-template {task_id} --priority high-medium --include-partial --force --output data/manual_assets.task_{task_id}.gaps.yaml",
                    f"assetmap run {task_id} --manual-file data/manual_assets.task_{task_id}.gaps.yaml",
                ]
            )
        if self._has_rerunnable_dns_gap(coverage_rows) or any(item.get("tool_failures") for item in dns_items):
            commands.append(f"assetmap run {task_id} --from-stage subdomains --rerun-subdomain-tools")
        if self._has_rerunnable_service_gap(coverage_rows) or self._service_rerun_needed(service_items) or url_items:
            commands.append(f"assetmap run {task_id} --from-stage classify --rerun-classify")
        if self._visual_retry_needed(visual_items):
            commands.append(f"assetmap url-discover {task_id} --retry-failed")
        if dns_items or service_items or url_items or any(item.get("review_type") != "automatic_retry" for item in visual_items):
            commands.append(f"assetmap import-review {task_id} --file data/review_workorder.task_{task_id}.yaml")
        if commands:
            commands.append(f"assetmap deliver {task_id}")
        return commands

    def _has_coverage_gap(self, coverage_rows: list[dict[str, Any]], stage: str) -> bool:
        return any(row.get("环节") == stage and row.get("缺口等级") not in {"", "无"} for row in coverage_rows)

    def _has_rerunnable_dns_gap(self, coverage_rows: list[dict[str, Any]]) -> bool:
        return any(
            row.get("环节") == "子域名/DNS"
            and row.get("指标") in {"根域名解析覆盖", "子域名枚举质量"}
            and row.get("缺口等级") not in {"", "无"}
            for row in coverage_rows
        )

    def _has_rerunnable_service_gap(self, coverage_rows: list[dict[str, Any]]) -> bool:
        return any(
            row.get("环节") == "服务识别/URL"
            and row.get("指标") in {"Web 服务入口覆盖", "URL 入口关联质量"}
            and row.get("缺口等级") not in {"", "无"}
            for row in coverage_rows
        )

    def _service_rerun_needed(self, service_items: list[dict[str, Any]]) -> bool:
        rerunnable_types = {"missing_url_entry", "web_like_non_web", "unknown_service"}
        return any(item.get("review_type") in rerunnable_types for item in service_items)

    def _visual_retry_needed(self, visual_items: list[dict[str, Any]]) -> bool:
        return any(
            item.get("review_type") == "automatic_retry"
            or item.get("analysis_error")
            or not item.get("identify_method")
            for item in visual_items
        )

    def _dns_items(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._with_review_fields({
                "priority": row.get("复核优先级"),
                "review_type": row.get("复核类型") or "manual_review",
                "root_domain": row.get("根域名"),
                "unit": row.get("归属单位"),
                "reason": row.get("复核原因"),
                "suggested_action": row.get("建议动作"),
                "subdomain_count": row.get("子域名数量"),
                "public_ip_count": row.get("公网IP数量"),
                "tool_failures": row.get("工具失败"),
                "third_party_cname_clues": row.get("第三方CNAME线索"),
            })
            for row in rows
            if row.get("复核优先级") not in {"", "无"}
        ]

    def _service_items(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._with_review_fields({
                "priority": row.get("复核优先级"),
                "unit": row.get("单位"),
                "endpoint": f"{row.get('IP')}:{row.get('端口')}",
                "review_type": row.get("复核类型") or "manual_review",
                "asset_kind": row.get("资产类型"),
                "service": row.get("服务"),
                "product": row.get("产品"),
                "reason": row.get("分类依据"),
                "suggested_action": row.get("建议动作"),
                "manual_url_candidates": self._manual_url_candidates(row),
            })
            for row in rows
            if row.get("复核优先级") not in {"", "无"}
        ]

    def _url_items(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._with_review_fields({
                "priority": row.get("复核优先级"),
                "unit": row.get("单位"),
                "endpoint": f"{row.get('IP')}:{row.get('端口')}",
                "url_sample": row.get("URL入口样例"),
                "coverage_result": row.get("覆盖结论"),
                "suggested_action": row.get("建议动作"),
            })
            for row in rows
            if row.get("复核优先级") not in {"", "无"}
        ]

    def _manual_url_candidates(self, row: dict[str, Any]) -> list[str]:
        ip = str(row.get("IP") or "").strip()
        port = row.get("端口")
        if not ip or not port:
            return []
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            return []
        if port_int in {80, 8080, 8000, 8090, 8888}:
            return [f"http://{ip}:{port_int}/"]
        if port_int in {443, 8443, 9443, 8900}:
            return [f"https://{ip}:{port_int}/"]
        return [f"http://{ip}:{port_int}/", f"https://{ip}:{port_int}/"]

    def _visual_items(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._with_review_fields({
                "priority": row.get("复核优先级"),
                "review_type": row.get("复核类型") or self._visual_review_type(row),
                "unit": row.get("单位"),
                "url": row.get("URL"),
                "identify_method": row.get("识别方式"),
                "confidence": row.get("识别置信度"),
                "reason": row.get("复核原因"),
                "suggested_action": row.get("建议动作"),
                "screenshot": row.get("截图"),
                "package_screenshot_path": self._package_screenshot_path(row.get("截图")),
                "analysis_error": row.get("分析错误"),
                "manual_result_fields": [
                    "confirmed_system_name",
                    "confirmed_site_purpose",
                    "confirmed_owner_unit",
                    "reviewer",
                    "reviewed_at",
                    "notes",
                ],
            })
            for row in rows
            if row.get("复核优先级") not in {"", "无"}
        ]

    def _with_review_fields(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            **item,
            "review_status": "pending",
            "review_notes": "",
            "reviewer": "",
            "reviewed_at": "",
            "source_urls": [],
        }

    def _visual_review_type(self, row: dict[str, Any]) -> str:
        if row.get("分析错误") or not row.get("识别方式"):
            return "automatic_retry"
        if row.get("识别方式") == "http_probe_fallback":
            return "manual_http_fallback_review"
        if "低价值错误/拦截页面" in str(row.get("复核原因") or ""):
            return "manual_low_value_page_review"
        confidence = row.get("识别置信度")
        try:
            low_confidence = confidence not in {"", None} and float(confidence) < 0.5
        except (TypeError, ValueError):
            low_confidence = False
        if "乱码" in str(row.get("复核原因") or ""):
            return "manual_text_review"
        if low_confidence:
            return "manual_low_confidence_review"
        return "manual_review"

    def _package_screenshot_path(self, screenshot: Any) -> str:
        if not screenshot:
            return ""
        return f"screenshots/{Path(str(screenshot)).name}"
