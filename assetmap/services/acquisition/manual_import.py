from __future__ import annotations

import ipaddress
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import yaml
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from assetmap.models import Company, CompanyAssetLink, CompanyEdge, DnsRecord, InternetAsset, ScanTask, SourceRawRecord, SubdomainRecord, WebEntrypoint
from assetmap.services.operations.maintenance import MaintenanceService
from assetmap.services.mapping.subdomain import normalize_hostname
from assetmap.utils import normalize_company_name


SOURCE_TOOL = "manual_import"
DEFAULT_MANUAL_ASSET_TEMPLATE_PATH = Path("data/manual_assets.example.yaml")

MANUAL_ASSET_TEMPLATE = """# 手工补充资产模板
# 用法：
#   1. 复制本文件，例如复制为 data/manual_assets.yaml
#   2. 删除不需要的字段，填入你额外掌握的资产
#   3. 执行：assetmap import-assets <task_id> --file data/manual_assets.yaml
#
# 字段说明：
#   units: 单位列表，每个单位下面填写该单位归属的资产
#   unit: 单位/公司名称
#   domains: 主域名/根域名，会进入后续子域名枚举和 DNS 解析
#   subdomains: 已知子域名，会进入 DNS 解析
#   ips: 已知公网 IP，会直接进入 port-scan
#   urls: 已确认 Web 入口，会进入 URL 截图识别和报告
#   apps: APP 备案或应用线索
#   mini_programs: 小程序备案或小程序线索
#   wechat_official_accounts: 微信公众号
#   wechat_service_accounts: 微信服务号
#   emails: 邮箱线索
#   source_urls/review_checklist/review_status/notes: 复核留痕，不会当作资产导入
#   如果确认某单位没有独立互联网资产，保留空资产列表并设置 review_status: no_assets_found

units:
  - unit: 示例集团有限公司
    domains:
      - example.cn
      - example.com
    subdomains:
      - www.example.cn
      - oa.example.cn
    ips:
      - 1.2.3.4
    urls:
      - url: https://portal.example.cn/login
        system_name: 示例门户系统
        site_purpose: 统一入口/登录门户
    apps:
      - name: 示例 APP
        package: cn.example.app
    mini_programs:
      - name: 示例小程序
        appid: wx123456
    wechat_official_accounts:
      - name: 示例公众号
        account: example-official
    wechat_service_accounts:
      - name: 示例服务号
        account: example-service
    emails:
      - security@example.cn
    source_urls:
      - https://beian.miit.gov.cn/
    review_checklist:
      - source: 工信部ICP备案
        status: done
        notes: 已核验备案域名
      - source: 官网/搜索引擎
        status: pending
        notes: ""
      - source: 微信公众号/小程序
        status: pending
        notes: ""
      - source: 应用商店/APP备案
        status: pending
        notes: ""
      - source: 内部台账/防火墙/邮箱
        status: pending
        notes: ""
    review_status: pending
    notes: ""

  - unit: 示例子公司有限公司
    domains:
      - child-example.cn
    subdomains:
      - portal.child-example.cn
    ips:
      - 8.8.8.8
    urls:
      - http://portal.child-example.cn/
    apps:
      - name: 子公司 APP
        package: cn.example.child
    mini_programs: []
    wechat_official_accounts: []
    wechat_service_accounts: []
    emails: []
    source_urls: []
    review_status: pending
    notes: ""

  - unit: 示例无独立资产项目公司
    domains: []
    subdomains: []
    ips: []
    urls: []
    apps: []
    mini_programs: []
    wechat_official_accounts: []
    wechat_service_accounts: []
    emails: []
    source_urls:
      - https://beian.miit.gov.cn/
    review_checklist:
      - source: 工信部ICP备案
        status: done
        notes: 未发现备案
      - source: 官网/搜索引擎
        status: done
        notes: 未发现独立官网
    review_status: no_assets_found
    notes: 人工复核未发现独立互联网资产
"""

ASSET_FIELDS = {
    "apps": "app",
    "APP": "app",
    "app": "app",
    "app备案": "app",
    "APP备案": "app",
    "备案APP": "app",
    "mini_programs": "mini_program",
    "mini_program备案": "mini_program",
    "小程序": "mini_program",
    "小程序备案": "mini_program",
    "微信小程序": "mini_program",
    "微信小程序备案": "mini_program",
    "wechat_official_accounts": "wechat_official_account",
    "wechat_accounts": "wechat_official_account",
    "official_accounts": "wechat_official_account",
    "公众号": "wechat_official_account",
    "微信公众号": "wechat_official_account",
    "公众号备案": "wechat_official_account",
    "微信公众号备案": "wechat_official_account",
    "wechat_service_accounts": "wechat_service_account",
    "service_accounts": "wechat_service_account",
    "服务号": "wechat_service_account",
    "微信服务号": "wechat_service_account",
    "服务号备案": "wechat_service_account",
    "微信服务号备案": "wechat_service_account",
    "emails": "email",
    "email": "email",
    "邮箱": "email",
    "邮箱地址": "email",
}


@dataclass
class ManualImportResult:
    task_id: int
    units: int = 0
    units_with_input: int = 0
    domains: int = 0
    subdomains: int = 0
    ips: int = 0
    urls: int = 0
    assets: int = 0
    no_asset_reviews: int = 0
    merged_links: int = 0
    skipped: int = 0
    empty_units: list[str] | None = None
    warnings: list[str] | None = None


def write_manual_asset_template(path: Path | str = DEFAULT_MANUAL_ASSET_TEMPLATE_PATH, overwrite: bool = False) -> Path:
    file_path = Path(path)
    if file_path.exists() and not overwrite:
        return file_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(MANUAL_ASSET_TEMPLATE, encoding="utf-8")
    return file_path


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _has_value(item: Any) -> bool:
    if isinstance(item, dict):
        return any(_has_value(value) for value in item.values())
    if isinstance(item, list):
        return any(_has_value(value) for value in item)
    return bool(_text(item))


def _identifier(item: Any, keys: tuple[str, ...]) -> str:
    if isinstance(item, dict):
        for key in keys:
            value = _text(item.get(key))
            if value:
                return value
        return ""
    return _text(item)


def _field_items(group: dict[str, Any], *field_names: str) -> list[Any]:
    items: list[Any] = []
    for field_name in field_names:
        if field_name in group:
            items.extend(_items(group.get(field_name)))
    return items


def _display_name(item: Any, identifier: str) -> str:
    if isinstance(item, dict):
        return _text(item.get("name") or item.get("display_name") or item.get("title") or identifier)
    return identifier


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and ip not in ipaddress.ip_network("198.18.0.0/15")


def _named_identifier(asset_type: str, item: Any) -> str:
    if not isinstance(item, dict):
        return _text(item).lower()
    if asset_type == "app":
        keys = ("package", "bundle", "appid", "app_id", "identifier", "filing_number", "name")
    elif asset_type == "mini_program":
        keys = ("appid", "app_id", "filing_number", "identifier", "name")
    elif asset_type in {"wechat_official_account", "wechat_service_account"}:
        keys = ("account", "ghid", "identifier", "filing_number", "name")
    elif asset_type == "email":
        keys = ("email", "identifier", "name")
    else:
        keys = ("identifier", "name")
    value = _identifier(item, keys)
    if asset_type == "mini_program" and value.isdigit() and _text(item.get("filing_number")):
        value = _text(item.get("filing_number"))
    value = "".join(value.split())
    if asset_type in {"app", "email"}:
        return value.lower()
    return value


def _merge_raw_payload(existing: Any, source: str, raw: Any) -> dict[str, Any]:
    if isinstance(existing, dict) and existing.get("sources") and isinstance(existing.get("evidence"), list):
        payload = {**existing}
        sources = list(payload.get("sources") or [])
        evidence = list(payload.get("evidence") or [])
    else:
        payload = {}
        sources = []
        evidence = []
        if existing:
            old_source = existing.get("source") if isinstance(existing, dict) else "existing"
            old_raw = existing.get("raw") if isinstance(existing, dict) and "raw" in existing else existing
            sources.append(str(old_source or "existing"))
            evidence.append({"source": str(old_source or "existing"), "raw": old_raw})
    if source not in sources:
        sources.append(source)
    if not any(item.get("source") == source and item.get("raw") == raw for item in evidence if isinstance(item, dict)):
        evidence.append({"source": source, "raw": raw})
    payload["sources"] = sources
    payload["evidence"] = evidence
    return payload


class ManualAssetImportService:
    def __init__(self, session: Session, progress: Callable[[str], None] | None = None) -> None:
        self.session = session
        self.progress = progress
        self._result: ManualImportResult | None = None

    def _log(self, message: str) -> None:
        if self.progress:
            try:
                self.progress(message)
            except OSError:
                self.progress = None

    def _skip(self, message: str) -> None:
        if not self._result:
            return
        self._result.skipped += 1
        warnings = self._result.warnings or []
        if len(warnings) < 50:
            warnings.append(message)
        self._result.warnings = warnings
        self._log(f"[manual] skip: {message}")

    def run(self, task_id: int, file_path: Path) -> ManualImportResult:
        task = self.session.get(ScanTask, task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("Manual asset file must be a YAML object.")

        result = ManualImportResult(task_id=task_id, warnings=[])
        self._result = result
        self._log(f"[manual] importing assets from: {file_path}")
        for group in self._groups(data):
            result.units += 1
            company = self._resolve_company(task, self._group_company_name(group, data))
            self._log(f"[manual] unit: {company.name}")
            if self._group_has_asset_values(group) or self._is_no_asset_review(group):
                result.units_with_input += 1
            else:
                empty_units = result.empty_units or []
                empty_units.append(company.name)
                result.empty_units = empty_units
            result.domains += self._import_domains(task, company, group)
            result.subdomains += self._import_subdomains(task, company, group)
            result.ips += self._import_ips(task, company, group)
            result.urls += self._import_urls(task, company, group)
            result.assets += self._import_named_assets(task, company, group)
            result.no_asset_reviews += self._import_review_attestation(task, company, group)
        dedupe = MaintenanceService(self.session).dedupe_asset_links(task_id)
        result.merged_links = dedupe.removed_links
        self._log(
            "[manual] completed: "
            f"domains={result.domains}, subdomains={result.subdomains}, ips={result.ips}, "
            f"urls={result.urls}, named_assets={result.assets}, merged_links={result.merged_links}, skipped={result.skipped}"
        )
        return result

    def _import_review_attestation(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        review_status = _text(group.get("review_status") or group.get("复核状态"))
        if review_status not in {"no_assets_found", "无资产", "确认无资产", "未发现资产"}:
            return 0
        payload = {
            "unit": company.name,
            "review_status": "no_assets_found",
            "source_urls": _items(group.get("source_urls") or group.get("来源链接")),
            "review_checklist": _items(group.get("review_checklist") or group.get("复核清单")),
            "notes": _text(group.get("notes") or group.get("备注")),
            "raw": group,
        }
        parameter_hash = hashlib.sha256(
            json.dumps(
                {"task_id": task.id, "unit": company.name, "review_status": "no_assets_found"},
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        row = self.session.exec(
            select(SourceRawRecord).where(
                SourceRawRecord.task_id == task.id,
                SourceRawRecord.source == SOURCE_TOOL,
                SourceRawRecord.action == "no_assets_found",
                SourceRawRecord.parameter_hash == parameter_hash,
            )
        ).first()
        if row:
            row.response_json = payload
        else:
            row = SourceRawRecord(
                task_id=task.id,
                source=SOURCE_TOOL,
                action="no_assets_found",
                parameter_hash=parameter_hash,
                request_payload={"unit": company.name},
                response_json=payload,
            )
        self.session.add(row)
        self.session.commit()
        return 1

    def _group_has_asset_values(self, group: dict[str, Any]) -> bool:
        field_names = (
            "domains",
            "root_domains",
            "主域名",
            "根域名",
            "备案域名",
            "备案网站",
            "网站备案",
            "域名",
            "subdomains",
            "子域名",
            "子域名资产",
            "ips",
            "ip",
            "IP",
            "IP地址",
            "公网IP",
            "公网IP地址",
            "urls",
            "web_urls",
            "websites",
            "网站",
            "网站入口",
            "Web入口",
            "URL",
            *ASSET_FIELDS.keys(),
        )
        return any(_has_value(group.get(field_name)) for field_name in field_names if field_name in group)

    def _is_no_asset_review(self, group: dict[str, Any]) -> bool:
        return _text(group.get("review_status") or group.get("复核状态")) in {
            "no_assets_found",
            "无资产",
            "确认无资产",
            "未发现资产",
        }

    def _groups(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        groups = [
            item
            for item in _items(data.get("units") or data.get("单位") or data.get("companies"))
            if isinstance(item, dict)
        ]
        return groups or [data]

    def _group_company_name(self, group: dict[str, Any], data: dict[str, Any]) -> Any:
        return (
            group.get("unit")
            or group.get("单位")
            or group.get("company")
            or group.get("company_name")
            or group.get("name")
            or data.get("unit")
            or data.get("单位")
            or data.get("company")
        )

    def _resolve_company(self, task: ScanTask, company_name: Any) -> Company:
        name = _text(company_name)
        if name:
            company = self._company_by_name(name)
            if company:
                return company
            company = Company(name=name, normalized_name=normalize_company_name(name), raw_payload={"source": SOURCE_TOOL})
            self.session.add(company)
            self.session.commit()
            self.session.refresh(company)
            return company

        root = self._root_company(task.id)
        if root:
            return root

        fallback = self._company_by_name(task.target)
        if fallback:
            return fallback
        fallback = Company(name=task.target, normalized_name=normalize_company_name(task.target), raw_payload={"source": SOURCE_TOOL})
        self.session.add(fallback)
        self.session.commit()
        self.session.refresh(fallback)
        return fallback

    def _company_by_name(self, name: str) -> Company | None:
        normalized = normalize_company_name(name)
        return self.session.exec(select(Company).where(Company.normalized_name == normalized)).first()

    def _root_company(self, task_id: int) -> Company | None:
        edges = self.session.exec(select(CompanyEdge).where(CompanyEdge.task_id == task_id)).all()
        if edges:
            child_ids = {edge.child_company_id for edge in edges}
            root_ids = sorted({edge.parent_company_id for edge in edges if edge.parent_company_id not in child_ids})
            if root_ids:
                return self.session.get(Company, root_ids[0])
        link = self.session.exec(
            select(CompanyAssetLink).where(CompanyAssetLink.task_id == task_id).order_by(CompanyAssetLink.company_id)
        ).first()
        return self.session.get(Company, link.company_id) if link else None

    def _company_for_item(self, task: ScanTask, default_company: Company, item: Any) -> Company:
        if isinstance(item, dict):
            company_name = (
                item.get("unit")
                or item.get("单位")
                or item.get("company")
                or item.get("company_name")
                or item.get("owner_company")
                or item.get("归属公司")
            )
            if company_name:
                return self._resolve_company(task, company_name)
        return default_company

    def _import_domains(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        count = 0
        for item in _field_items(group, "domains", "root_domains", "主域名", "根域名", "备案域名", "备案网站", "网站备案", "域名"):
            domain = normalize_hostname(_identifier(item, ("domain", "root_domain", "host", "identifier", "name")))
            if not domain:
                if _has_value(item):
                    self._skip(f"invalid domain item: {item}")
                continue
            owner = self._company_for_item(task, company, item)
            asset = self._upsert_asset("icp_domain", domain, _display_name(item, domain), item)
            count += self._link_asset(task.id, owner, asset, item)
        return count

    def _import_subdomains(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        count = 0
        roots = self._known_roots(task.id)
        for item in _field_items(group, "subdomains", "子域名", "子域名资产"):
            fqdn = normalize_hostname(_identifier(item, ("fqdn", "subdomain", "host", "identifier", "name")))
            if not fqdn:
                if _has_value(item):
                    self._skip(f"invalid subdomain item: {item}")
                continue
            owner = self._company_for_item(task, company, item)
            root = self._match_root(fqdn, roots)
            asset = self._upsert_asset("subdomain", fqdn, _display_name(item, fqdn), item)
            self._link_asset(task.id, owner, asset, item)
            count += self._upsert_subdomain(task.id, root, fqdn)
        return count

    def _import_ips(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        count = 0
        for item in _field_items(group, "ips", "ip", "IP", "IP地址", "公网IP", "公网IP地址"):
            value = _identifier(item, ("ip", "value", "identifier", "name"))
            if not _is_public_ip(value):
                if _has_value(item):
                    self._skip(f"invalid or non-public IP: {value}")
                continue
            owner = self._company_for_item(task, company, item)
            asset = self._upsert_asset("ip", value, _display_name(item, value), item)
            self._link_asset(task.id, owner, asset, item)
            record_type = "AAAA" if ":" in value else "A"
            count += self._upsert_dns_record(task.id, value, record_type)
        return count

    def _import_named_assets(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        count = 0
        for field, asset_type in ASSET_FIELDS.items():
            for item in _items(group.get(field)):
                identifier = _named_identifier(asset_type, item)
                if not identifier:
                    if _has_value(item):
                        self._skip(f"missing identifier for {asset_type}: {item}")
                    continue
                owner = self._company_for_item(task, company, item)
                asset = self._upsert_asset(asset_type, identifier, _display_name(item, identifier), item)
                count += self._link_asset(task.id, owner, asset, item)
        return count

    def _import_urls(self, task: ScanTask, company: Company, group: dict[str, Any]) -> int:
        count = 0
        for item in _field_items(group, "urls", "web_urls", "websites", "网站", "网站入口", "Web入口", "URL"):
            raw_url = _identifier(item, ("url", "web_url", "href", "identifier", "name"))
            normalized = _normalize_url(raw_url)
            if not normalized:
                if _has_value(item):
                    self._skip(f"invalid URL item: {item}")
                continue
            owner = self._company_for_item(task, company, item)
            count += self._upsert_web_entrypoint(task.id, owner, normalized, raw_url, item)
        return count

    def _upsert_asset(self, asset_type: str, identifier: str, display_name: str, raw: Any) -> InternetAsset:
        asset = self.session.exec(
            select(InternetAsset).where(
                InternetAsset.asset_type == asset_type,
                InternetAsset.normalized_identifier == identifier,
            )
        ).first()
        payload = {"source": SOURCE_TOOL, "raw": raw}
        if asset:
            if display_name and (asset.display_name == asset.normalized_identifier or display_name != identifier):
                asset.display_name = display_name
            asset.raw_payload = _merge_raw_payload(asset.raw_payload, SOURCE_TOOL, raw)
            asset.updated_at = _utcnow()
        else:
            asset = InternetAsset(
                asset_type=asset_type,
                normalized_identifier=identifier,
                display_name=display_name,
                raw_payload=payload,
            )
        self.session.add(asset)
        self.session.commit()
        self.session.refresh(asset)
        return asset

    def _upsert_web_entrypoint(self, task_id: int, company: Company, normalized_url: str, raw_url: str, raw: Any) -> int:
        parsed = urlparse(normalized_url)
        host = (parsed.hostname or "").lower()
        port = _url_port(parsed)
        row = self.session.exec(
            select(WebEntrypoint).where(
                WebEntrypoint.scan_task_id == task_id,
                WebEntrypoint.normalized_url == normalized_url,
            )
        ).first()
        is_new = row is None
        if not row:
            row = WebEntrypoint(
                scan_task_id=task_id,
                host=host,
                url=raw_url or normalized_url,
                normalized_url=normalized_url,
                final_url=normalized_url,
                evidence={},
            )
        row.host = host or row.host
        target_ip = _identifier(raw, ("ip", "target_ip", "IP")) if isinstance(raw, dict) else ""
        if target_ip:
            row.target_ip = target_ip
        manual_port = _safe_int(_identifier(raw, ("port", "端口"))) if isinstance(raw, dict) else None
        row.port = manual_port or port
        row.title = _identifier(raw, ("title", "标题")) if isinstance(raw, dict) and _identifier(raw, ("title", "标题")) else row.title
        row.final_url = normalized_url
        row.observed_at = _utcnow()
        row.evidence = _merge_web_evidence(row.evidence, company, raw)
        self.session.add(row)
        try:
            self.session.commit()
            return 1 if is_new else 0
        except IntegrityError:
            self.session.rollback()
            return 0

    def _link_asset(self, task_id: int, company: Company, asset: InternetAsset, raw: Any) -> int:
        exists = self.session.exec(
            select(CompanyAssetLink).where(
                CompanyAssetLink.task_id == task_id,
                CompanyAssetLink.company_id == company.id,
                CompanyAssetLink.asset_id == asset.id,
            )
        ).first()
        if exists:
            payload = {**(exists.raw_payload or {})}
            sources = list(payload.get("sources") or [exists.source_tool])
            if SOURCE_TOOL not in sources:
                payload["sources"] = [*sources, SOURCE_TOOL]
                payload["evidence"] = [
                    *list(payload.get("evidence") or [{"source": exists.source_tool, "raw": exists.raw_payload}]),
                    {"source": SOURCE_TOOL, "raw": raw},
                ]
                exists.raw_payload = payload
                self.session.add(exists)
                self.session.commit()
            return 0
        self.session.add(
            CompanyAssetLink(
                task_id=task_id,
                company_id=company.id,
                asset_id=asset.id,
                source_tool=SOURCE_TOOL,
                raw_payload={"source": SOURCE_TOOL, "raw": raw},
            )
        )
        try:
            self.session.commit()
            return 1
        except IntegrityError:
            self.session.rollback()
            return 0

    def _known_roots(self, task_id: int) -> list[str]:
        rows = self.session.exec(
            select(InternetAsset)
            .join(CompanyAssetLink, CompanyAssetLink.asset_id == InternetAsset.id)
            .where(CompanyAssetLink.task_id == task_id, InternetAsset.asset_type == "icp_domain")
        ).all()
        return sorted({domain for row in rows if (domain := normalize_hostname(row.normalized_identifier))}, key=len, reverse=True)

    def _match_root(self, fqdn: str, roots: list[str]) -> str:
        for root in roots:
            if fqdn == root or fqdn.endswith(f".{root}"):
                return root
        parts = fqdn.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

    def _upsert_subdomain(self, task_id: int, root_domain: str, fqdn: str) -> int:
        row = self.session.exec(
            select(SubdomainRecord).where(
                SubdomainRecord.scan_task_id == task_id,
                SubdomainRecord.fqdn == fqdn,
            )
        ).first()
        if row:
            if SOURCE_TOOL not in row.sources:
                row.sources = [*row.sources, SOURCE_TOOL]
                row.last_seen_at = _utcnow()
                self.session.add(row)
                self.session.commit()
            return 0
        row = SubdomainRecord(scan_task_id=task_id, root_domain=root_domain, fqdn=fqdn, sources=[SOURCE_TOOL])
        self.session.add(row)
        self.session.commit()
        return 1

    def _upsert_dns_record(self, task_id: int, ip: str, record_type: str) -> int:
        exists = self.session.exec(
            select(DnsRecord).where(
                DnsRecord.scan_task_id == task_id,
                DnsRecord.fqdn == ip,
                DnsRecord.record_type == record_type,
                DnsRecord.value == ip,
            )
        ).first()
        if exists:
            return 0
        self.session.add(
            DnsRecord(
                scan_task_id=task_id,
                fqdn=ip,
                root_domain=ip,
                record_type=record_type,
                value=ip,
                raw_payload={"source": SOURCE_TOOL, "kind": "manual_ip"},
            )
        )
        self.session.commit()
        return 1


def _normalize_url(value: str) -> str:
    raw = _text(value)
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    netloc = host
    try:
        port = int(parsed.port) if parsed.port else None
    except ValueError:
        return ""
    if port:
        default = 443 if parsed.scheme == "https" else 80
        if port != default:
            netloc = f"{host}:{port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))


def _url_port(parsed: Any) -> int:
    port = _parsed_port(parsed)
    if port:
        return port
    return 443 if parsed.scheme == "https" else 80


def _parsed_port(parsed: Any) -> int | None:
    try:
        return int(parsed.port) if parsed.port else None
    except ValueError:
        return None


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _merge_web_evidence(existing: Any, company: Company, raw: Any) -> dict[str, Any]:
    evidence = dict(existing or {}) if isinstance(existing, dict) else {}
    evidence["manual_import"] = {
        "source": SOURCE_TOOL,
        "unit": company.name,
        "raw": raw,
    }
    if isinstance(raw, dict):
        visual = {
            "analysis_method": "manual",
            "system_name": _identifier(raw, ("system_name", "system", "系统名称")),
            "site_purpose": _identifier(raw, ("site_purpose", "purpose", "用途")),
            "page_type": _identifier(raw, ("page_type", "页面类型")),
            "confidence": _identifier(raw, ("confidence", "置信度")) or "人工确认",
        }
        if any(value for key, value in visual.items() if key != "analysis_method"):
            evidence["visual_analysis"] = {**(evidence.get("visual_analysis") or {}), **visual}
    return evidence
