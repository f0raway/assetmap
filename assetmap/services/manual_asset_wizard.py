"""手动资产补充 TUI 向导服务"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Callable

import questionary
import yaml
from questionary import Style
from sqlmodel import Session, select

from assetmap.models import Company, CompanyEdge
from assetmap.services.manual_import import ManualAssetImportService, ManualImportResult


CUSTOM_STYLE = Style([
    ("qmark", "fg:cyan bold"),
    ("question", "bold"),
    ("answer", "fg:green bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan"),
    ("selected", "fg:green bold"),
])


ASSET_TYPES: list[dict[str, Any]] = [
    {
        "key": "domain",
        "label": "域名（根域名，会触发子域名枚举）",
        "yaml_field": "domains",
        "prompt": "域名（多个用逗号、分号或换行分隔）:",
        "item_mode": "string",
    },
    {
        "key": "subdomain",
        "label": "子域名（直接进入 DNS 解析）",
        "yaml_field": "subdomains",
        "prompt": "子域名（多个用逗号、分号或换行分隔）:",
        "item_mode": "string",
    },
    {
        "key": "ip",
        "label": "IP 地址（直接进入端口扫描）",
        "yaml_field": "ips",
        "prompt": "IP 地址（多个用逗号、分号或换行分隔）:",
        "item_mode": "string",
    },
    {
        "key": "url",
        "label": "URL（直接进入截图识别）",
        "yaml_field": "urls",
        "prompt": "URL（多个用逗号、分号或换行分隔）:",
        "item_mode": "url",
        "detail_fields": [
            ("system_name", "系统名称（可选）"),
            ("site_purpose", "用途说明（可选）"),
        ],
    },
    {
        "key": "app",
        "label": "App（APP 备案或应用线索）",
        "yaml_field": "apps",
        "prompt": "App 名称（多个用逗号、分号或换行分隔）:",
        "item_mode": "named",
        "primary_field": "name",
        "detail_fields": [
            ("package", "包名/Bundle ID（可选）"),
            ("filing_number", "备案号（可选）"),
            ("source_url", "来源链接（可选）"),
        ],
    },
    {
        "key": "mini_program",
        "label": "微信小程序（小程序备案或小程序线索）",
        "yaml_field": "mini_programs",
        "prompt": "小程序名称（多个用逗号、分号或换行分隔）:",
        "item_mode": "named",
        "primary_field": "name",
        "detail_fields": [
            ("appid", "AppID（可选）"),
            ("filing_number", "备案号（可选）"),
            ("source_url", "来源链接（可选）"),
        ],
    },
    {
        "key": "wechat_official_account",
        "label": "微信公众号",
        "yaml_field": "wechat_official_accounts",
        "prompt": "公众号名称/账号（多个用逗号、分号或换行分隔）:",
        "item_mode": "named",
        "primary_field": "name",
        "detail_fields": [
            ("account", "公众号账号（可选）"),
            ("ghid", "原始 ID/GHID（可选）"),
            ("source_url", "来源链接（可选）"),
        ],
    },
    {
        "key": "wechat_service_account",
        "label": "微信服务号",
        "yaml_field": "wechat_service_accounts",
        "prompt": "服务号名称/账号（多个用逗号、分号或换行分隔）:",
        "item_mode": "named",
        "primary_field": "name",
        "detail_fields": [
            ("account", "服务号账号（可选）"),
            ("ghid", "原始 ID/GHID（可选）"),
            ("source_url", "来源链接（可选）"),
        ],
    },
    {
        "key": "email",
        "label": "邮箱",
        "yaml_field": "emails",
        "prompt": "邮箱地址（多个用逗号、分号或换行分隔）:",
        "item_mode": "string",
    },
]

ASSET_TYPE_BY_KEY = {item["key"]: item for item in ASSET_TYPES}
ASSET_TYPE_BY_LABEL = {item["label"]: item for item in ASSET_TYPES}
BATCH_SPLIT_PATTERN = re.compile(r"[，,；;\n\r]+")


class ManualAssetWizardService:
    """手动资产补充 TUI 向导服务"""

    def __init__(self, session: Session, progress: Callable[[str], None] | None = None) -> None:
        self.session = session
        self.progress = progress
        self.added_count = 0

    def _log(self, message: str) -> None:
        if self.progress:
            try:
                self.progress(message)
            except OSError:
                self.progress = None

    def run(self, task_id: int) -> bool:
        """运行手动资产补充向导"""
        self._log("")
        self._log("─" * 50)
        self._log("  批量添加手动资产")
        self._log("─" * 50)
        self._log("")

        companies = self._get_companies(task_id)
        if not companies:
            self._log("✗ 未发现关联公司，请先运行 discover")
            return False

        while True:
            asset_type = self._select_asset_type()
            if asset_type is None:
                break

            raw_values = questionary.text(asset_type["prompt"], style=CUSTOM_STYLE).ask()
            values = self._parse_values(raw_values)
            if not values:
                self._log("✗ 输入为空，跳过")
                continue

            company_name = self._select_company(companies)
            if not company_name:
                self._log("✗ 未选择归属单位，跳过")
                continue

            detail_mode = self._ask_detail_mode(asset_type, len(values))
            items = self._build_items(asset_type, values, detail_mode)
            if not items:
                self._log("✗ 未生成有效资产，跳过")
                continue

            added = self._add_assets(task_id, asset_type["key"], items, company_name)
            self.added_count += added
            self._log(f"✓ 已添加 {added} 条: {', '.join(values[:5])}{' ...' if len(values) > 5 else ''} → {company_name}")

            continue_add = questionary.confirm(
                "继续添加？",
                default=True,
                style=CUSTOM_STYLE,
            ).ask()

            if not continue_add:
                break

        self._log("")
        self._log(f"本次共添加 {self.added_count} 条资产")
        return self.added_count > 0

    def _select_asset_type(self) -> dict[str, Any] | None:
        label = questionary.select(
            "资产类型:",
            choices=[item["label"] for item in ASSET_TYPES],
            style=CUSTOM_STYLE,
        ).ask()
        if label is None:
            return None
        return ASSET_TYPE_BY_LABEL[str(label)]

    def _select_company(self, companies: list[Company]) -> str | None:
        company_choices = [f"{c.name}" for c in companies[:20]]
        company_choices.append("其他（手动输入）")

        company_choice = questionary.select(
            "归属单位:",
            choices=company_choices,
            style=CUSTOM_STYLE,
        ).ask()

        if company_choice is None:
            return None
        if company_choice == "其他（手动输入）":
            company_name = questionary.text("公司名称:", style=CUSTOM_STYLE).ask()
            return str(company_name or "").strip() or None
        return str(company_choice)

    def _ask_detail_mode(self, asset_type: dict[str, Any], count: int) -> bool:
        if not asset_type.get("detail_fields"):
            return False
        if count == 1:
            message = "是否补充详细信息？"
        else:
            message = f"已输入 {count} 条，是否逐条补充详细信息？"
        answer = questionary.confirm(message, default=False, style=CUSTOM_STYLE).ask()
        return bool(answer)

    def _build_items(self, asset_type: dict[str, Any], values: list[str], detail_mode: bool) -> list[Any]:
        mode = asset_type["item_mode"]
        if mode == "string":
            return values

        items = []
        for value in values:
            if mode == "url":
                item = {"url": value}
            else:
                item = {str(asset_type.get("primary_field") or "name"): value}

            if detail_mode:
                for field_name, prompt in asset_type.get("detail_fields", []):
                    answer = questionary.text(f"{value} - {prompt}:", style=CUSTOM_STYLE).ask()
                    if answer:
                        item[field_name] = str(answer).strip()
            items.append(item)
        return items

    def _parse_values(self, raw_values: Any) -> list[str]:
        raw = str(raw_values or "").strip()
        if not raw:
            return []
        values = []
        for item in BATCH_SPLIT_PATTERN.split(raw):
            value = item.strip()
            if value and value not in values:
                values.append(value)
        return values

    def _get_companies(self, task_id: int) -> list[Company]:
        """获取任务关联的公司列表"""
        edges = self.session.exec(
            select(CompanyEdge).where(CompanyEdge.task_id == task_id)
        ).all()

        company_ids = set()
        for edge in edges:
            company_ids.add(edge.parent_company_id)
            company_ids.add(edge.child_company_id)

        if company_ids:
            companies = []
            for cid in company_ids:
                company = self.session.get(Company, cid)
                if company:
                    companies.append(company)
            return companies

        return list(self.session.exec(select(Company)).all()[:20])

    def _add_asset(
        self,
        task_id: int,
        asset_type: str,
        value: str,
        company_name: str,
        extra_info: dict[str, Any] | None = None,
    ) -> int:
        """添加单条资产，保留给旧调用和测试使用。"""
        config = ASSET_TYPE_BY_KEY.get(asset_type, ASSET_TYPE_BY_KEY["domain"])
        if asset_type == "url":
            items: list[Any] = [{"url": value, **(extra_info or {})}]
        elif config["item_mode"] == "named":
            items = [{str(config.get("primary_field") or "name"): value, **(extra_info or {})}]
        else:
            items = [value]
        return self._add_assets(task_id, asset_type, items, company_name)

    def _add_assets(
        self,
        task_id: int,
        asset_type: str,
        items: list[Any],
        company_name: str,
    ) -> int:
        """添加一批同类型资产到数据库。"""
        field = self._get_yaml_field(asset_type)
        data = {
            "units": [
                {
                    "unit": company_name,
                    field: items,
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f, allow_unicode=True)
            temp_path = Path(f.name)

        try:
            service = ManualAssetImportService(self.session, progress=self.progress)
            result = service.run(task_id, temp_path)
            return self._result_added_count(result)
        finally:
            temp_path.unlink()

    def _result_added_count(self, result: ManualImportResult) -> int:
        return result.domains + result.subdomains + result.ips + result.urls + result.assets

    def _get_yaml_field(self, asset_type: str) -> str:
        """获取 YAML 字段名"""
        config = ASSET_TYPE_BY_KEY.get(asset_type)
        if config:
            return str(config["yaml_field"])
        return "domains"
