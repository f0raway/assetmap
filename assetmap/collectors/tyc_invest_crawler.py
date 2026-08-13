#!/usr/bin/env python3
"""Tianyancha investment drill-down crawler inspired by ENScan_GO.

The implementation focuses on three data surfaces:
1. company base information
2. outbound investments
3. ICP website records

It uses the same Tianyancha web API shape that ENScan_GO uses. A valid
Tianyancha browser session is required: tycid and auth_token.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Iterable
from urllib.parse import urlencode

import requests


LOGGER = logging.getLogger("tyc_invest_crawler")

TYC_CAPI = "https://capi.tianyancha.com"
TYC_WEB = "https://www.tianyancha.com"

ABNORMAL_STATUS = {
    "注销",
    "吊销",
    "停业",
    "清算",
    "歇业",
    "关闭",
    "撤销",
    "迁出",
    "经营异常",
    "严重违法失信",
}

# Enterprise discovery uses a deliberately conservative, fixed request policy.
# These values are implementation details rather than user-facing scan options.
FIXED_REQUEST_DELAY_SECONDS = 0.2
FIXED_REQUEST_TIMEOUT_SECONDS = 6
FIXED_MAX_RETRIES = 3


class TYCError(RuntimeError):
    """Raised when Tianyancha rejects or fails a request."""


class TYCRiskVerificationError(TYCError):
    """Raised when Tianyancha asks the account to complete risk verification."""


class CrawlAborted(TYCError):
    def __init__(self, message: str, result: "CrawlResult") -> None:
        super().__init__(message)
        self.result = result


@dataclass
class CompanyBasic:
    pid: str
    name: str = ""
    legal_person: str = ""
    reg_status: str = ""
    phone: str = ""
    email: str = ""
    reg_capital: str = ""
    established_on: str = ""
    address: str = ""
    business_scope: str = ""
    credit_code: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Investment:
    pid: str
    name: str
    legal_person: str = ""
    reg_status: str = ""
    percent: str = ""
    percent_value: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ICPRecord:
    website_name: str = ""
    website: str = ""
    domain: str = ""
    icp_license: str = ""
    company_name: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AppRecord:
    name: str = ""
    category: str = ""
    version: str = ""
    updated_at: str = ""
    description: str = ""
    logo: str = ""
    bundle_id: str = ""
    link: str = ""
    market: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class WechatAccountRecord:
    name: str = ""
    wechat_id: str = ""
    description: str = ""
    qrcode: str = ""
    avatar: str = ""
    account_type: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class MiniProgramRecord:
    name: str = ""
    category: str = ""
    logo: str = ""
    qrcode: str = ""
    read_num: str = ""
    filing_number: str = ""
    examine_date: str = ""
    organizing_name: str = ""
    organizing_company_id: str = ""
    organizing_property: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class QueueItem:
    pid: str
    name: str
    depth: int
    ref: str


@dataclass
class CrawlOptions:
    threshold: float = 50.0
    max_depth: int = 0
    skip_abnormal: bool = True


@dataclass
class ClientOptions:
    tycid: str = ""
    auth_token: str = ""
    timeout: int = FIXED_REQUEST_TIMEOUT_SECONDS
    delay: float = FIXED_REQUEST_DELAY_SECONDS
    max_retries: int = FIXED_MAX_RETRIES
    proxy: str | None = None


@dataclass
class RunOptions:
    name: str | None = None
    pid: str | None = None
    root_name: str | None = None
    output: Path | None = None
    csv_dir: Path | None = None
    fresh: bool = False


@dataclass
class CrawlResult:
    source: str
    generated_at: str
    criteria: dict[str, Any]
    companies: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    crawler_state: dict[str, Any] = field(default_factory=dict)


CheckpointCallback = Callable[[CrawlResult], None]
ProgressCallback = Callable[[str, dict[str, Any]], None]


class TianyanchaClient:
    def __init__(
        self,
        tycid: str,
        auth_token: str,
        *,
        timeout: int = FIXED_REQUEST_TIMEOUT_SECONDS,
        delay: float = FIXED_REQUEST_DELAY_SECONDS,
        max_retries: int = FIXED_MAX_RETRIES,
        proxy: str | None = None,
    ) -> None:
        if not tycid or not auth_token:
            raise ValueError("tycid and auth_token are required")

        self.tycid = tycid
        self.auth_token = auth_token
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.session = requests.Session()
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def search_company(self, keyword: str) -> list[dict[str, Any]]:
        payload = {
            "key": keyword,
            "pageNum": "1",
            "pageSize": "20",
            "referer": "search",
            "sortType": "0",
            "word": keyword,
        }
        data = self._request_json(
            "POST",
            f"{TYC_CAPI}/cloud-tempest/web/searchCompanyV4",
            json_body=payload,
        )
        return data.get("data", {}).get("companyList", []) or []

    def resolve_company(self, keyword: str) -> QueueItem:
        companies = self.search_company(keyword)
        if not companies:
            raise TYCError(f"No Tianyancha search result for keyword: {keyword}")

        normalized_keyword = _strip_html(keyword).strip()
        selected = companies[0]
        for company in companies:
            candidate = _strip_html(str(company.get("name") or company.get("comName") or ""))
            if candidate == normalized_keyword:
                selected = company
                break

        pid = str(selected.get("id") or selected.get("graphId") or "").strip()
        name = _strip_html(str(selected.get("name") or selected.get("comName") or keyword)).strip()
        if not pid:
            raise TYCError(f"Search result does not contain company id: {selected}")
        return QueueItem(pid=pid, name=name, depth=0, ref="root")

    def get_base_info(self, pid: str) -> CompanyBasic:
        params = urlencode({"id": pid})
        data = self._request_json(
            "GET",
            f"{TYC_CAPI}/cloud-other-information/companyinfo/baseinfo/web?{params}",
        )
        raw = data.get("data") or {}
        return CompanyBasic(
            pid=str(raw.get("id") or pid),
            name=str(raw.get("name") or ""),
            legal_person=str(raw.get("legalPersonName") or raw.get("legalPerson") or ""),
            reg_status=str(raw.get("regStatus") or ""),
            phone=str(raw.get("phoneNumber") or raw.get("phone") or ""),
            email=str(raw.get("email") or ""),
            reg_capital=str(raw.get("regCapitalAmount") or raw.get("regCapital") or ""),
            established_on=_format_tyc_date(raw.get("fromTime") or raw.get("estiblishTime")),
            address=str(raw.get("taxAddress") or raw.get("regLocation") or raw.get("base") or ""),
            business_scope=str(raw.get("businessScope") or ""),
            credit_code=str(raw.get("creditCode") or raw.get("creditcode") or ""),
            raw=raw,
        )

    def list_investments(self, pid: str) -> list[Investment]:
        def fetch(page: int) -> tuple[int, int, list[dict[str, Any]]]:
            body = {
                "category": "-100",
                "percentLevel": "-100",
                "province": "-100",
                "gid": pid,
                "pageSize": "100",
                "pageNum": str(page),
            }
            data = self._request_json(
                "POST",
                f"{TYC_CAPI}/cloud-company-background/company/investListV2?_={int(time.time())}",
                json_body=body,
            )
            payload = data.get("data") or {}
            total = _first_int(payload, ["itemTotal", "count", "total", "pageBean.total"])
            rows = payload.get("result") or []
            return total, 100, rows

        investments: list[Investment] = []
        for row in self._page_all(fetch):
            percent = str(row.get("percent") or "")
            investments.append(
                Investment(
                    pid=str(row.get("id") or ""),
                    name=str(row.get("name") or ""),
                    legal_person=str(row.get("legalPersonName") or ""),
                    reg_status=str(row.get("regStatus") or ""),
                    percent=percent,
                    percent_value=parse_percent(percent),
                    raw=row,
                )
            )
        return investments

    def list_icp_records(self, pid: str) -> list[ICPRecord]:
        def fetch(page: int) -> tuple[int, int, list[dict[str, Any]]]:
            query = {
                "_": int(time.time()),
                "pageSize": 20,
                "graphId": pid,
                "id": pid,
                "gid": pid,
                "pageNum": page,
            }
            data = self._request_json(
                "GET",
                f"{TYC_CAPI}/cloud-intellectual-property/intellectualProperty/icpRecordList?{urlencode(query)}",
            )
            payload = data.get("data") or {}
            total = _first_int(payload, ["itemTotal", "count", "total", "pageBean.total"])
            rows = payload.get("item") or []
            return total, 20, rows

        records: list[ICPRecord] = []
        for row in self._page_all(fetch):
            for domain in _split_domains(row.get("ym")):
                records.append(
                    ICPRecord(
                        website_name=str(row.get("webName") or ""),
                        website=str(row.get("webSite") or ""),
                        domain=domain,
                        icp_license=str(row.get("liscense") or row.get("license") or ""),
                        company_name=str(row.get("companyName") or ""),
                        raw=row,
                    )
                )
        return records

    def list_apps(self, pid: str) -> list[AppRecord]:
        def fetch(page: int) -> tuple[int, int, list[dict[str, Any]]]:
            query = _page_query(pid, page, page_size=20)
            data = self._request_json(
                "GET",
                f"{TYC_CAPI}/cloud-business-state/v3/ar/appbkinfo?{urlencode(query)}",
            )
            payload = data.get("data") or {}
            total = _first_int(payload, ["itemTotal", "count", "total", "pageBean.total", "productinfo"])
            rows = payload.get("items") or []
            return total, 20, rows

        records: list[AppRecord] = []
        for row in self._page_all(fetch):
            records.append(
                AppRecord(
                    name=str(row.get("filterName") or row.get("name") or ""),
                    category=str(row.get("classes") or row.get("category") or ""),
                    version=str(row.get("version") or row.get("versionName") or ""),
                    updated_at=str(row.get("updateTime") or row.get("updated_at") or row.get("updateDate") or ""),
                    description=str(row.get("brief") or row.get("description") or ""),
                    logo=str(row.get("icon") or row.get("logo") or ""),
                    bundle_id=str(row.get("bundleId") or row.get("bundle_id") or ""),
                    link=str(row.get("url") or row.get("link") or row.get("downloadUrl") or ""),
                    market=str(row.get("market") or row.get("source") or ""),
                    raw=row,
                )
            )
        return records

    def list_wechat_accounts(self, pid: str) -> list[WechatAccountRecord]:
        def fetch(page: int) -> tuple[int, int, list[dict[str, Any]]]:
            query = _page_query(pid, page, page_size=20)
            data = self._request_json(
                "GET",
                f"{TYC_CAPI}/cloud-business-state/wechat/list?{urlencode(query)}",
            )
            payload = data.get("data") or {}
            total = _first_int(payload, ["itemTotal", "count", "total", "pageBean.total", "weChatCount"])
            rows = payload.get("resultList") or []
            return total, 20, rows

        records: list[WechatAccountRecord] = []
        for row in self._page_all(fetch):
            records.append(
                WechatAccountRecord(
                    name=str(row.get("title") or row.get("name") or ""),
                    wechat_id=str(row.get("publicNum") or row.get("wechat_id") or row.get("id") or ""),
                    description=str(row.get("recommend") or row.get("description") or ""),
                    qrcode=str(row.get("codeImg") or row.get("qrcode") or ""),
                    avatar=str(row.get("titleImgURL") or row.get("avatar") or ""),
                    account_type=_infer_wechat_account_type(row),
                    raw=row,
                )
            )
        return records

    def list_mini_programs(self, pid: str) -> list[MiniProgramRecord]:
        def fetch(page: int) -> tuple[int, int, list[dict[str, Any]]]:
            query = {
                "_": int(time.time() * 1000),
                "gid": pid,
                "pageSize": 10,
                "pageNum": page,
            }
            data = self._request_json(
                "GET",
                f"{TYC_CAPI}/cloud-intellectual-property/intellectualProperty/miniProgramIcpRecordList?{urlencode(query)}",
            )
            payload = data.get("data") or {}
            total = _first_int(payload, ["itemTotal", "count", "total", "pageBean.total"])
            rows = payload.get("miniProgramIcpRecordList") or []
            return total, 10, rows

        records: list[MiniProgramRecord] = []
        for row in self._page_all(fetch):
            detail = row.get("miniProgramIcpRecordDetail") or {}
            subject = detail.get("icpFilingSubjectInformation") or {}
            service = detail.get("icpFilingServiceInformation") or {}
            records.append(
                MiniProgramRecord(
                    name=str(row.get("serviceName") or service.get("serviceName") or ""),
                    filing_number=str(
                        row.get("serviceFilingNumber")
                        or service.get("icpLicenseNumber")
                        or ""
                    ),
                    examine_date=str(row.get("examineDate") or ""),
                    organizing_name=str(subject.get("organizingName") or ""),
                    organizing_company_id=str(subject.get("organizingCompanyId") or ""),
                    organizing_property=str(subject.get("organizingProperty") or ""),
                    raw=row,
                )
            )
        return records

    def _page_all(self, fetch: Any) -> Iterable[dict[str, Any]]:
        total, page_size, rows = fetch(1)
        yielded = 0
        for row in rows:
            yielded += 1
            yield row

        if total <= yielded or page_size <= 0:
            return

        pages = (total + page_size - 1) // page_size
        for page in range(2, pages + 1):
            _, _, rows = fetch(page)
            for row in rows:
                yield row

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = self._request(method, url, json_body=json_body)
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise TYCError(f"Response is not JSON: {url}") from exc

        state = data.get("state")
        if state and state != "ok":
            raise TYCError(f"Tianyancha returned state={state}: {data}")
        return data

    def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> str:
        headers = self._headers(url, has_json=json_body is not None)
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            if self.delay > 0:
                time.sleep(self.delay)
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    json=json_body,
                    timeout=self.timeout,
                    proxies=self.proxies,
                )
            except requests.RequestException as exc:
                last_error = exc
                LOGGER.warning("request failed, retrying %s/%s: %s", attempt, self.max_retries, exc)
                continue

            if response.status_code == 200:
                text = response.text
                self._raise_for_risk_text(text, url)
                return text

            if response.status_code in {429, 433} and attempt < self.max_retries:
                LOGGER.warning("request blocked with %s, retrying: %s", response.status_code, url)
                time.sleep(max(self.delay, 5))
                continue

            raise TYCError(f"HTTP {response.status_code} from Tianyancha: {url}")

        raise TYCError(f"request failed after retries: {url}") from last_error

    def _headers(self, url: str, *, has_json: bool) -> dict[str, str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.6367.60 Safari/537.36"
            ),
            "Accept": "text/html,application/json,application/xhtml+xml, image/jxr, */*",
            "Version": "TYC-Web",
            "Origin": TYC_WEB,
            "Referer": f"{TYC_WEB}/",
        }
        if "capi.tianyancha.com" in url:
            headers["X-Tycid"] = self.tycid
            headers["X-Auth-Token"] = self.auth_token
            if has_json:
                headers["Content-Type"] = "application/json"
        return headers

    @staticmethod
    def _raise_for_risk_text(text: str, url: str) -> None:
        if '"message":"mustlogin"' in text:
            raise TYCError("Tianyancha requires login; refresh tycid/auth_token")
        if "账号存在风险" in text:
            raise TYCRiskVerificationError(f"Tianyancha account risk verification is required: {url}")
        if "请输入中国大陆手机号" in text:
            raise TYCError("Tianyancha login state appears invalid or expired")
        if "当前暂时无法访问" in text:
            raise TYCError("Tianyancha temporarily blocked this IP")


def create_result(root: QueueItem, options: CrawlOptions) -> CrawlResult:
    result = CrawlResult(
        source=root.name or root.pid,
        generated_at=datetime.now(timezone.utc).isoformat(),
        criteria=_criteria(options),
    )
    _set_crawler_state(result, deque([root]), set(), status="running")
    return result


def fetch_company_payload(
    client: TianyanchaClient,
    pid: str,
) -> tuple[
    CompanyBasic,
    list[Investment],
    list[ICPRecord],
    list[AppRecord],
    list[WechatAccountRecord],
    list[MiniProgramRecord],
]:
    basic = client.get_base_info(pid)
    tasks = {
        "investments": lambda: client.list_investments(pid),
        "icp_records": lambda: client.list_icp_records(pid),
        "apps": lambda: client.list_apps(pid),
        "wechat_accounts": lambda: client.list_wechat_accounts(pid),
        "mini_programs": lambda: client.list_mini_programs(pid),
    }

    return (
        basic,
        tasks["investments"](),
        tasks["icp_records"](),
        tasks["apps"](),
        tasks["wechat_accounts"](),
        tasks["mini_programs"](),
    )


def crawl_company_tree(
    client: TianyanchaClient,
    result: CrawlResult,
    options: CrawlOptions,
    *,
    checkpoint: CheckpointCallback | None = None,
    progress: ProgressCallback | None = None,
) -> CrawlResult:
    if "completed_pids" in result.crawler_state:
        completed = set(result.crawler_state.get("completed_pids") or [])
    else:
        completed = {str(company.get("pid")) for company in result.companies if company.get("pid")}

    state_queue = result.crawler_state.get("queue") or []
    queue: Deque[QueueItem] = deque(_queue_item_from_dict(item) for item in state_queue)
    if not queue and not result.companies:
        raise TYCError("crawler state has no queue; create a new result before crawling")

    queued: set[str] = completed | {item.pid for item in queue}
    _set_crawler_state(result, queue, completed, status="running")
    _checkpoint(result, checkpoint)

    while queue:
        item = queue.popleft()
        if item.pid in completed:
            continue

        LOGGER.info("fetching company depth=%s pid=%s name=%s", item.depth, item.pid, item.name)
        _progress(
            progress,
            "company_started",
            {"pid": item.pid, "name": item.name, "depth": item.depth},
        )
        _set_crawler_state(result, deque([item, *queue]), completed, status="running")
        _checkpoint(result, checkpoint)
        try:
            (
                basic,
                investments,
                icp_records,
                apps,
                wechat_accounts,
                mini_programs,
            ) = fetch_company_payload(
                client,
                item.pid,
            )
        except TYCRiskVerificationError as exc:
            _set_crawler_state(result, deque([item, *queue]), completed, status="blocked")
            _checkpoint(result, checkpoint)
            _progress(progress, "blocked", {"pid": item.pid, "name": item.name, "error": str(exc)})
            raise CrawlAborted(
                f"{exc}. Open Tianyancha in the same account/network, complete verification, "
                "then refresh tycid/auth_token and rerun.",
                result,
            ) from exc

        company_name = basic.name or item.name
        company_record = (
            {
                "pid": item.pid,
                "name": company_name,
                "depth": item.depth,
                "ref": item.ref,
                "basic": asdict(basic),
                "investments": [asdict(investment) for investment in investments],
                "icp_records": [asdict(record) for record in icp_records],
                "apps": [asdict(app) for app in apps],
                "wechat_accounts": [asdict(account) for account in wechat_accounts],
                "wechat_service_accounts": [
                    asdict(account) for account in wechat_accounts if account.account_type == "service"
                ],
                "mini_programs": [asdict(program) for program in mini_programs],
                "digital_assets": _build_digital_assets(
                    item.pid,
                    company_name,
                    icp_records,
                    apps,
                    wechat_accounts,
                    mini_programs,
                ),
            }
        )
        _upsert_company(result, company_record)

        if options.max_depth and item.depth >= options.max_depth:
            completed.add(item.pid)
            _set_crawler_state(result, queue, completed, status="running")
            _checkpoint(result, checkpoint)
            continue

        for investment in investments:
            if not investment.pid:
                continue
            if investment.percent_value is None or investment.percent_value < options.threshold:
                continue
            if options.skip_abnormal and investment.reg_status in ABNORMAL_STATUS:
                continue

            edge = {
                "from_pid": item.pid,
                "from_name": basic.name or item.name,
                "to_pid": investment.pid,
                "to_name": investment.name,
                "percent": investment.percent,
                "percent_value": investment.percent_value,
                "depth": item.depth + 1,
            }
            result.edges.append(edge)

            if investment.pid not in completed and investment.pid not in queued:
                queued.add(investment.pid)
                queue.append(
                    QueueItem(
                        pid=investment.pid,
                        name=investment.name,
                        depth=item.depth + 1,
                        ref=(
                            f"{basic.name or item.name} invests "
                            f"{investment.percent_value:.2f}% in {investment.name}"
                        ),
                    )
                )

        completed.add(item.pid)
        _dedupe_edges(result)
        _set_crawler_state(result, queue, completed, status="running")
        _checkpoint(result, checkpoint)
        _progress(
            progress,
            "company_completed",
            {
                "pid": item.pid,
                "name": basic.name or item.name,
                "depth": item.depth,
                "queued": len(queue),
                "completed": len(completed),
            },
        )

    _set_crawler_state(result, queue, completed, status="done")
    _checkpoint(result, checkpoint)
    _progress(progress, "done", {"completed": len(completed), "edges": len(result.edges)})
    return result


def save_json(result: CrawlResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def load_json(path: Path) -> CrawlResult:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return CrawlResult(
        source=str(raw.get("source") or ""),
        generated_at=str(raw.get("generated_at") or datetime.now(timezone.utc).isoformat()),
        criteria=raw.get("criteria") or {},
        companies=raw.get("companies") or [],
        edges=raw.get("edges") or [],
        crawler_state=raw.get("crawler_state") or {},
    )


def build_client(options: ClientOptions) -> TianyanchaClient:
    return TianyanchaClient(
        tycid=options.tycid,
        auth_token=options.auth_token,
        delay=options.delay,
        timeout=options.timeout,
        max_retries=options.max_retries,
        proxy=options.proxy,
    )


def initialize_result(
    client: TianyanchaClient,
    run_options: RunOptions,
    crawl_options: CrawlOptions,
) -> CrawlResult:
    if run_options.pid:
        root = QueueItem(
            pid=run_options.pid,
            name=run_options.root_name or run_options.pid,
            depth=0,
            ref="root",
        )
    elif run_options.name:
        root = client.resolve_company(run_options.name)
    else:
        raise ValueError("run_options.name or run_options.pid is required")
    return create_result(root, crawl_options)


def run_crawl(
    client_options: ClientOptions,
    crawl_options: CrawlOptions | None = None,
    run_options: RunOptions | None = None,
    *,
    client: TianyanchaClient | None = None,
    result: CrawlResult | None = None,
    checkpoint: CheckpointCallback | None = None,
    progress: ProgressCallback | None = None,
) -> CrawlResult:
    """Run or resume a crawl from Python code.

    When ``run_options.output`` exists and ``fresh`` is false, the result is
    resumed from that JSON checkpoint. On risk verification, ``CrawlAborted`` is
    raised and its ``result`` attribute contains the latest saved state.
    """

    crawl_options = crawl_options or CrawlOptions()
    run_options = run_options or RunOptions()
    current_criteria = _criteria(crawl_options)
    client_instance = client

    if result is not None:
        if result.criteria and not _same_crawl_criteria(result.criteria, current_criteria):
            raise TYCError(
                f"Provided result criteria differ from crawl options: {result.criteria}"
            )
    elif run_options.output and run_options.output.exists() and not run_options.fresh:
        result = load_json(run_options.output)
        if result.criteria and not _same_crawl_criteria(result.criteria, current_criteria):
            raise TYCError(
                f"Existing checkpoint criteria differ from current args: {result.criteria}. "
                "Use the original args or pass fresh=True to start over."
            )
        _enqueue_companies_missing_asset_fields(result)
        LOGGER.info(
            "resume checkpoint: %s completed, %s queued, status=%s",
            len(result.crawler_state.get("completed_pids") or []),
            len(result.crawler_state.get("queue") or []),
            result.crawler_state.get("status") or "unknown",
        )
    else:
        client_instance = client_instance or build_client(client_options)
        result = initialize_result(client_instance, run_options, crawl_options)
        if run_options.output:
            save_json(result, run_options.output)

    if result.crawler_state.get("status") == "done":
        if run_options.csv_dir:
            _try_save_csvs(result, run_options.csv_dir)
        return result

    client_instance = client_instance or build_client(client_options)

    callbacks: list[CheckpointCallback] = []
    if run_options.output:
        callbacks.append(lambda checkpoint_result: save_json(checkpoint_result, run_options.output))
    if checkpoint:
        callbacks.append(checkpoint)

    def combined_checkpoint(checkpoint_result: CrawlResult) -> None:
        for callback in callbacks:
            callback(checkpoint_result)

    checkpoint_callback = combined_checkpoint if callbacks else None

    try:
        result = crawl_company_tree(
            client_instance,
            result,
            crawl_options,
            checkpoint=checkpoint_callback,
            progress=progress,
        )
    except CrawlAborted as exc:
        if run_options.csv_dir:
            _try_save_csvs(exc.result, run_options.csv_dir)
        raise

    if run_options.output:
        save_json(result, run_options.output)
    if run_options.csv_dir:
        _try_save_csvs(result, run_options.csv_dir)
    return result


def _try_save_csvs(result: CrawlResult, directory: Path) -> bool:
    try:
        save_csvs(result, directory)
        return True
    except OSError as exc:
        LOGGER.warning("CSV export skipped: %s", exc)
        return False


def save_csvs(result: CrawlResult, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for filename, fields, rows in _csv_exports(result):
        _write_csv(directory / filename, fields, rows)


def _csv_exports(result: CrawlResult) -> list[tuple[str, list[str], Iterable[dict[str, Any]]]]:
    return [
        (
            "companies.csv",
            [
                "pid",
                "name",
                "depth",
                "ref",
                "legal_person",
                "reg_status",
                "phone",
                "email",
                "reg_capital",
                "established_on",
                "address",
                "credit_code",
            ],
            _company_rows(result),
        ),
        (
            "investments.csv",
            [
                "from_pid",
                "from_name",
                "to_pid",
                "to_name",
                "legal_person",
                "reg_status",
                "percent",
                "percent_value",
            ],
            _nested_rows(
                result,
                "investments",
                {
                    "to_pid": "pid",
                    "to_name": "name",
                    "legal_person": "legal_person",
                    "reg_status": "reg_status",
                    "percent": "percent",
                    "percent_value": "percent_value",
                },
                parent_prefix="from",
            ),
        ),
        (
            "icp_records.csv",
            [
                "company_pid",
                "company_name",
                "website_name",
                "website",
                "domain",
                "icp_license",
                "record_company_name",
            ],
            _nested_rows(
                result,
                "icp_records",
                {
                    "website_name": "website_name",
                    "website": "website",
                    "domain": "domain",
                    "icp_license": "icp_license",
                    "record_company_name": "company_name",
                },
            ),
        ),
        (
            "apps.csv",
            [
                "company_pid",
                "company_name",
                "name",
                "category",
                "version",
                "updated_at",
                "description",
                "logo",
                "bundle_id",
                "link",
                "market",
            ],
            _nested_rows(
                result,
                "apps",
                {
                    "name": "name",
                    "category": "category",
                    "version": "version",
                    "updated_at": "updated_at",
                    "description": "description",
                    "logo": "logo",
                    "bundle_id": "bundle_id",
                    "link": "link",
                    "market": "market",
                },
            ),
        ),
        (
            "wechat_accounts.csv",
            [
                "company_pid",
                "company_name",
                "name",
                "wechat_id",
                "account_type",
                "description",
                "qrcode",
                "avatar",
            ],
            _nested_rows(
                result,
                "wechat_accounts",
                {
                    "name": "name",
                    "wechat_id": "wechat_id",
                    "account_type": "account_type",
                    "description": "description",
                    "qrcode": "qrcode",
                    "avatar": "avatar",
                },
            ),
        ),
        (
            "mini_programs.csv",
            [
                "company_pid",
                "company_name",
                "name",
                "category",
                "logo",
                "qrcode",
                "read_num",
                "filing_number",
                "examine_date",
                "organizing_name",
                "organizing_company_id",
                "organizing_property",
            ],
            _nested_rows(
                result,
                "mini_programs",
                {
                    "name": "name",
                    "category": "category",
                    "logo": "logo",
                    "qrcode": "qrcode",
                    "read_num": "read_num",
                    "filing_number": "filing_number",
                    "examine_date": "examine_date",
                    "organizing_name": "organizing_name",
                    "organizing_company_id": "organizing_company_id",
                    "organizing_property": "organizing_property",
                },
            ),
        ),
        (
            "digital_assets.csv",
            [
                "company_pid",
                "company_name",
                "asset_type",
                "name",
                "identifier",
                "url",
                "filing_number",
                "description",
            ],
            (asset for company in result.companies for asset in company.get("digital_assets", [])),
        ),
    ]


def _write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _company_rows(result: CrawlResult) -> Iterable[dict[str, Any]]:
    for company in result.companies:
        basic = company.get("basic") or {}
        yield {
            "pid": company.get("pid", ""),
            "name": company.get("name", ""),
            "depth": company.get("depth", ""),
            "ref": company.get("ref", ""),
            "legal_person": basic.get("legal_person", ""),
            "reg_status": basic.get("reg_status", ""),
            "phone": basic.get("phone", ""),
            "email": basic.get("email", ""),
            "reg_capital": basic.get("reg_capital", ""),
            "established_on": basic.get("established_on", ""),
            "address": basic.get("address", ""),
            "credit_code": basic.get("credit_code", ""),
        }


def _nested_rows(
    result: CrawlResult,
    key: str,
    mapping: dict[str, str],
    *,
    parent_prefix: str = "company",
) -> Iterable[dict[str, Any]]:
    for company in result.companies:
        parent = {
            f"{parent_prefix}_pid": company.get("pid", ""),
            f"{parent_prefix}_name": company.get("name", ""),
        }
        for record in company.get(key, []):
            yield parent | {out_key: record.get(in_key, "") for out_key, in_key in mapping.items()}


def _criteria(options: CrawlOptions) -> dict[str, Any]:
    return {
        "investment_percent_gt": options.threshold,
        "max_depth": options.max_depth or None,
        "skip_abnormal": options.skip_abnormal,
    }


def _same_crawl_criteria(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return {
        "investment_percent_gt": left.get("investment_percent_gt"),
        "max_depth": left.get("max_depth"),
        "skip_abnormal": left.get("skip_abnormal"),
    } == {
        "investment_percent_gt": right.get("investment_percent_gt"),
        "max_depth": right.get("max_depth"),
        "skip_abnormal": right.get("skip_abnormal"),
    }


def _queue_item_from_dict(data: dict[str, Any]) -> QueueItem:
    return QueueItem(
        pid=str(data.get("pid") or ""),
        name=str(data.get("name") or ""),
        depth=int(data.get("depth") or 0),
        ref=str(data.get("ref") or ""),
    )


def _set_crawler_state(
    result: CrawlResult,
    queue: Deque[QueueItem],
    completed: set[str],
    *,
    status: str,
) -> None:
    result.crawler_state = {
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "queue": [asdict(item) for item in queue],
        "completed_pids": sorted(pid for pid in completed if pid),
    }


def _checkpoint(result: CrawlResult, checkpoint: CheckpointCallback | None) -> None:
    if checkpoint is not None:
        checkpoint(result)


def _progress(progress: ProgressCallback | None, event: str, payload: dict[str, Any]) -> None:
    if progress is not None:
        progress(event, payload)


def _upsert_company(result: CrawlResult, company_record: dict[str, Any]) -> None:
    pid = str(company_record.get("pid") or "")
    for index, existing in enumerate(result.companies):
        if str(existing.get("pid") or "") == pid:
            result.companies[index] = company_record
            return
    result.companies.append(company_record)


def _dedupe_edges(result: CrawlResult) -> None:
    seen: set[tuple[str, str, int]] = set()
    deduped: list[dict[str, Any]] = []
    for edge in result.edges:
        key = (
            str(edge.get("from_pid") or ""),
            str(edge.get("to_pid") or ""),
            int(edge.get("depth") or 0),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    result.edges = deduped


def _enqueue_companies_missing_asset_fields(result: CrawlResult) -> None:
    required_keys = {
        "apps",
        "wechat_accounts",
        "wechat_service_accounts",
        "mini_programs",
        "digital_assets",
    }
    missing = [
        company
        for company in result.companies
        if not required_keys.issubset(set(company.keys()))
    ]
    if not missing:
        return

    completed = set(result.crawler_state.get("completed_pids") or [])
    queue = [_queue_item_from_dict(item) for item in result.crawler_state.get("queue") or []]
    queued = {item.pid for item in queue}
    for company in missing:
        pid = str(company.get("pid") or "")
        if not pid:
            continue
        completed.discard(pid)
        if pid in queued:
            continue
        queue.append(
            QueueItem(
                pid=pid,
                name=str(company.get("name") or pid),
                depth=int(company.get("depth") or 0),
                ref=str(company.get("ref") or "asset-field-upgrade"),
            )
        )
        queued.add(pid)
    _set_crawler_state(result, deque(queue), completed, status="running")


def _build_digital_assets(
    company_pid: str,
    company_name: str,
    icp_records: list[ICPRecord],
    apps: list[AppRecord],
    wechat_accounts: list[WechatAccountRecord],
    mini_programs: list[MiniProgramRecord],
) -> list[dict[str, str]]:
    assets: list[dict[str, str]] = []
    for record in icp_records:
        assets.append(
            {
                "company_pid": company_pid,
                "company_name": company_name,
                "asset_type": "domain",
                "name": record.website_name,
                "identifier": record.domain,
                "url": record.website,
                "filing_number": record.icp_license,
                "description": "",
            }
        )
    for record in apps:
        assets.append(
            {
                "company_pid": company_pid,
                "company_name": company_name,
                "asset_type": "app",
                "name": record.name,
                "identifier": record.bundle_id,
                "url": record.link,
                "filing_number": "",
                "description": record.description,
            }
        )
    for record in wechat_accounts:
        assets.append(
            {
                "company_pid": company_pid,
                "company_name": company_name,
                "asset_type": "wechat_service" if record.account_type == "service" else "wechat",
                "name": record.name,
                "identifier": record.wechat_id,
                "url": "",
                "filing_number": "",
                "description": record.description,
            }
        )
    for record in mini_programs:
        assets.append(
            {
                "company_pid": company_pid,
                "company_name": company_name,
                "asset_type": "mini_program",
                "name": record.name,
                "identifier": record.organizing_company_id,
                "url": "",
                "filing_number": record.filing_number,
                "description": record.organizing_name,
            }
        )
    return assets


def parse_percent(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {"-", "--"}:
        return None
    text = text.replace("%", "").replace("％", "").strip()
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    return float(match.group(0))


def _strip_html(value: str) -> str:
    return re.sub(r"<[^>]+>", "", value)


def _format_tyc_date(value: Any) -> str:
    if value in (None, "", "-"):
        return ""
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp = timestamp / 1000
        return datetime.fromtimestamp(timestamp).date().isoformat()
    text = str(value).strip()
    if text.isdigit():
        return _format_tyc_date(int(text))
    return text


def _first_int(data: dict[str, Any], keys: list[str]) -> int:
    for key in keys:
        value = _get_nested(data, key)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _get_nested(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _split_domains(value: Any) -> list[str]:
    if isinstance(value, list):
        raw_domains = value
    else:
        raw_domains = re.split(r"[,，;\s]+", str(value or ""))
    return [str(domain).strip() for domain in raw_domains if str(domain).strip()]


def _page_query(pid: str, page: int, *, page_size: int) -> dict[str, Any]:
    return {
        "_": int(time.time()),
        "pageSize": page_size,
        "graphId": pid,
        "id": pid,
        "gid": pid,
        "pageNum": page,
    }


def _infer_wechat_account_type(row: dict[str, Any]) -> str:
    for key in (
        "accountType",
        "publicType",
        "type",
        "serviceType",
        "wechatType",
        "bizType",
    ):
        value = str(row.get(key) or "")
        if "服务" in value or value.lower() == "service":
            return "service"
        if "订阅" in value or value.lower() == "subscription":
            return "subscription"
    return ""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch Tianyancha company base info, ICP records, and recursively owned investments.",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--name", help="Company keyword/name to search on Tianyancha")
    target.add_argument("--pid", help="Tianyancha company id. Skips search when provided")

    parser.add_argument("--root-name", help="Display name when --pid is used")
    parser.add_argument("--tycid", default="", help="Tianyancha X-Tycid")
    parser.add_argument("--auth-token", default="", help="Tianyancha X-Auth-Token")
    parser.add_argument("--threshold", type=float, default=50.0, help="Drill down investments greater than this percent")
    parser.add_argument("--max-depth", type=int, default=0, help="0 means unlimited")
    parser.add_argument("--output", type=Path, default=Path("output/tyc_result.json"), help="JSON output path")
    parser.add_argument("--fresh", action="store_true", help="Ignore an existing output checkpoint and start over")
    parser.add_argument("--csv-dir", type=Path, help="Optional directory for companies/investments/icp CSV files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    client_options = ClientOptions(
        tycid=args.tycid or "",
        auth_token=args.auth_token or "",
    )
    crawl_options = CrawlOptions(
        threshold=args.threshold,
        max_depth=args.max_depth,
    )
    run_options = RunOptions(
        name=args.name,
        pid=args.pid,
        root_name=args.root_name,
        output=args.output,
        csv_dir=args.csv_dir,
        fresh=args.fresh,
    )

    try:
        result = run_crawl(
            client_options,
            crawl_options,
            run_options,
        )
    except CrawlAborted as exc:
        result = exc.result
        LOGGER.error("%s", exc)
        LOGGER.error("partial result saved: %s", args.output)
        return 2

    LOGGER.info(
        "done: %s companies, %s qualifying investment edges, json=%s",
        len(result.companies),
        len(result.edges),
        args.output,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (TYCError, ValueError) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
