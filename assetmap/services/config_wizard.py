"""TUI 配置向导服务"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import questionary
import yaml
from questionary import Style

from assetmap.config import AppConfig, DEFAULT_CONFIG_PATH, load_config, public_config_dump
from assetmap.services.environment import _configured_secret


# 自定义样式
CUSTOM_STYLE = Style([
    ("qmark", "fg:cyan bold"),
    ("question", "bold"),
    ("answer", "fg:green bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan"),
    ("selected", "fg:green bold"),
    ("separator", "fg:gray"),
    ("instruction", "fg:gray"),
    ("text", ""),
])


class ConfigWizardService:
    """TUI 配置向导服务"""

    def __init__(self, progress: Callable[[str], None] | None = None) -> None:
        self.progress = progress
        self.config_data: dict[str, Any] = {}

    def _log(self, message: str) -> None:
        if self.progress:
            try:
                self.progress(message)
            except OSError:
                self.progress = None

    def run(self, config_path: Path = DEFAULT_CONFIG_PATH) -> bool:
        """运行配置向导"""
        self._log("")
        self._log("=" * 50)
        self._log("  assetmap 完整配置向导")
        self._log("=" * 50)
        self._log("")

        config = self._load_base_config(config_path)
        if config is None:
            return False

        self.config_data = config.model_dump(mode="json")

        self._step_database()
        self._step_org()
        self._step_enscan()
        self._step_tools()
        self._step_port_scan()
        self._step_fofa()
        self._step_dns()
        self._step_ai()
        self._step_web_probe()
        self._step_url_discovery()
        self._step_summary(config_path)

        return True

    def _load_base_config(self, config_path: Path) -> AppConfig | None:
        if not config_path.exists():
            return AppConfig()

        use_existing = questionary.confirm(
            "检测到已有配置文件，是否基于现有配置修改并覆盖保存？",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()
        if not use_existing:
            self._log("配置取消")
            return None
        return load_config(config_path)

    def _section(self, index: int, total: int, title: str, description: str) -> None:
        self._log("")
        self._log("─" * 50)
        self._log(f"Step {index}/{total}: {title}")
        self._log("─" * 50)
        self._log(description)
        self._log("")

    def _field(self, key: str, usage: str) -> None:
        self._log(f"{key}")
        self._log(f"用途：{usage}")

    def _ask_text(self, section: str, name: str, usage: str, *, secret: bool = False) -> str:
        value = str(self.config_data[section][name])
        key = f"{section}.{name}"
        self._field(key, usage)
        if secret:
            if _configured_secret(value):
                self._log("当前已配置；直接回车会保留原值。")
            answer = questionary.password(f"{key}:", style=CUSTOM_STYLE).ask()
            result = value if answer in (None, "") else str(answer)
        else:
            answer = questionary.text(f"{key}:", default=value, style=CUSTOM_STYLE).ask()
            result = value if answer is None else str(answer)
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_int(self, section: str, name: str, usage: str) -> int:
        value = int(self.config_data[section][name])
        key = f"{section}.{name}"
        self._field(key, usage)
        while True:
            answer = questionary.text(f"{key}:", default=str(value), style=CUSTOM_STYLE).ask()
            if answer is None or str(answer).strip() == "":
                result = value
                break
            try:
                result = int(str(answer).strip())
                break
            except ValueError:
                self._log("请输入整数。")
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_float(self, section: str, name: str, usage: str) -> float:
        value = float(self.config_data[section][name])
        key = f"{section}.{name}"
        self._field(key, usage)
        while True:
            answer = questionary.text(f"{key}:", default=str(value), style=CUSTOM_STYLE).ask()
            if answer is None or str(answer).strip() == "":
                result = value
                break
            try:
                result = float(str(answer).strip())
                break
            except ValueError:
                self._log("请输入数字。")
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_bool(self, section: str, name: str, usage: str) -> bool:
        value = bool(self.config_data[section][name])
        key = f"{section}.{name}"
        self._field(key, usage)
        answer = questionary.confirm(f"{key}:", default=value, style=CUSTOM_STYLE).ask()
        result = value if answer is None else bool(answer)
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_list(self, section: str, name: str, usage: str) -> list[str]:
        value = [str(item) for item in self.config_data[section][name]]
        key = f"{section}.{name}"
        self._field(key, usage)
        self._log("多个值请用英文逗号分隔；留空表示空列表。")
        answer = questionary.text(f"{key}:", default=", ".join(value), style=CUSTOM_STYLE).ask()
        raw = "" if answer is None else str(answer)
        result = [item.strip() for item in raw.split(",") if item.strip()]
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_int_list(self, section: str, name: str, usage: str) -> list[int]:
        value = [int(item) for item in self.config_data[section][name]]
        key = f"{section}.{name}"
        self._field(key, usage)
        self._log("多个状态码请用英文逗号分隔；留空表示空列表。")
        while True:
            answer = questionary.text(f"{key}:", default=", ".join(str(item) for item in value), style=CUSTOM_STYLE).ask()
            raw = "" if answer is None else str(answer).strip()
            if not raw:
                result: list[int] = []
                break
            try:
                result = [int(item.strip()) for item in raw.split(",") if item.strip()]
                break
            except ValueError:
                self._log("请输入整数状态码，例如：200, 301, 302, 401, 403")
        self.config_data[section][name] = result
        self._log("")
        return result

    def _ask_choice(self, section: str, name: str, usage: str, choices: list[str]) -> str:
        value = str(self.config_data[section][name])
        key = f"{section}.{name}"
        self._field(key, usage)
        default = value if value in choices else choices[0]
        answer = questionary.select(key + ":", choices=choices, default=default, style=CUSTOM_STYLE).ask()
        result = default if answer is None else str(answer)
        self.config_data[section][name] = result
        self._log("")
        return result

    def _set_fixed(self, section: str, name: str, value: Any, usage: str, reason: str) -> None:
        key = f"{section}.{name}"
        self._field(key, usage)
        self._log(reason)
        self.config_data[section][name] = value
        self._log("")

    def _step_database(self) -> None:
        self._section(1, 10, "数据库", "配置本地任务、资产、报告等数据的存储位置。")
        self._ask_text("database", "url", "create_db_and_engine 会使用它连接 SQLite；默认写入 data/assetmap.db。")

    def _step_org(self) -> None:
        self._section(2, 10, "企业关系", "配置企业股权穿透和控股关系判断规则。")
        self._ask_float("org", "control_threshold", "discovery 阶段判断母子公司控制关系的持股比例阈值。")
        self._ask_int("org", "max_depth", "enscan 采集企业投资关系时允许递归展开的最大层级。")

    def _step_enscan(self) -> None:
        self._section(3, 10, "企业数据采集", "配置天眼查/ENScan 采集器，用于发现股权、备案、域名、App、小程序等企业资产线索。")
        self._ask_text("enscan", "script", "discover 阶段通过该脚本启动企业数据采集器。")
        self._ask_text("enscan", "output_dir", "discover 阶段保存 enscan 原始 JSON 结果的目录。")
        self._ask_int("enscan", "timeout_seconds", "discover 阶段等待 enscan 子进程完成的最长时间。")
        self._ask_text("enscan", "tycid", "传给天眼查采集脚本的 TYCID；未配置会阻止 discover 阶段运行。", secret=True)
        self._ask_text("enscan", "auth_token", "传给天眼查采集脚本的 Auth Token；未配置会阻止 discover 阶段运行。", secret=True)
        self._ask_float("enscan", "request_delay_seconds", "采集脚本每次请求之间的延迟，用于降低触发风控的概率。")
        self._ask_int("enscan", "request_timeout_seconds", "采集脚本单个 HTTP 请求的超时时间。")
        self._ask_int("enscan", "asset_workers", "采集脚本并发处理资产详情的 worker 数。")
        self._ask_bool("enscan", "verbose", "是否让采集脚本输出更详细的调试日志。")

    def _step_tools(self) -> None:
        self._section(4, 10, "外部工具", "配置 subfinder、dnsx、nmap 的路径、命令模板和超时策略。")
        self._ask_text("tools", "tools_dir", "ToolResolver 会优先在该目录下查找已安装的外部工具。")
        self._ask_list("tools", "subdomain_tools_enabled", "subdomains 阶段启用哪些子域名工具；常用值：subfinder, dnsx。")
        self._ask_int("tools", "subdomain_tool_timeout_seconds", "每个子域名工具命令的最长运行时间。")
        self._ask_text("tools", "subfinder_command", "subdomains 阶段执行 subfinder 的命令模板，支持 {binary}/{domain}/{output}。")
        self._ask_text("tools", "dnsx_command", "subdomains 阶段执行 dnsx 的命令模板，支持 {binary}/{domain}/{wordlist}/{output}。")
        self._ask_text("tools", "wordlist", "dnsx 爆破子域名时使用的字典路径，env-check 也会检查它是否存在。")
        self._ask_text("tools", "nmap_command", "单目标主动端口扫描命令模板，支持 {binary}/{target}/{xml_output}/{normal_output}。")
        self._ask_choice("tools", "nmap_mode", "nmap_scan 根据该值选择批量扫描 batch 或逐目标扫描 single。", ["batch", "single"])
        self._ask_text("tools", "nmap_batch_command", "批量主动端口扫描命令模板，batch 模式使用，支持 {targets_file}/{xml_output}/{normal_output}。")
        self._ask_int("tools", "nmap_max_workers", "single 模式下并发执行 nmap 的最大 worker 数。")
        self._ask_int("tools", "nmap_timeout_seconds", "nmap 扫描和服务识别命令的超时时间。")
        self._ask_text("tools", "nmap_service_detect_command", "classify 阶段对已知端口补充服务识别时使用的 nmap 命令模板。")

    def _step_port_scan(self) -> None:
        self._section(5, 10, "端口扫描", "配置端口扫描数据来源，以及哪些主机来源会进入扫描目标列表。")
        self._ask_list("port_scan", "sources_enabled", "port-scan 阶段启用的数据源；常用值：nmap, fofa。")
        self._ask_list("port_scan", "target_sources_enabled", "nmap 主动扫描目标来源；常用值：ai, manual, dns_public。")

    def _step_fofa(self) -> None:
        self._section(6, 10, "FOFA", "配置 FOFA 被动资产检索，用于补充域名、IP、端口、协议、标题和服务信息。")
        self._ask_text("fofa", "base_url", "FOFA API 服务地址；fofa 服务会用它拼接查询接口。")
        self._ask_text("fofa", "email", "FOFA API 账号邮箱；启用 fofa 数据源时必须配置。")
        self._ask_text("fofa", "api_key", "FOFA API Key；启用 fofa 数据源时必须配置。", secret=True)
        self._ask_text("fofa", "fields", "FOFA 返回字段列表，影响后续端口合并、Web 分类和报告内容。")
        self._ask_int("fofa", "size", "每次 FOFA 查询最多返回的结果数量。")
        self._ask_bool("fofa", "full", "是否启用 FOFA full 查询参数，取决于账号权限和查询需求。")
        self._ask_int("fofa", "timeout_seconds", "FOFA API HTTP 请求超时时间。")

    def _step_dns(self) -> None:
        self._section(7, 10, "DNS", "配置子域名解析阶段的 DNS 查询超时、解析器和并发。")
        self._ask_float("dns", "timeout_seconds", "单次 DNS 查询超时时间。")
        self._ask_float("dns", "lifetime_seconds", "DNS 解析任务整体生命周期超时时间。")
        self._ask_list("dns", "nameservers", "自定义 DNS 服务器列表；留空时使用系统默认解析器。")
        self._ask_int("dns", "max_workers", "DNS 并发解析的最大 worker 数。")

    def _step_ai(self) -> None:
        self._section(8, 10, "AI", "仅配置 OpenAI 兼容接口。AI 用于 DNS 真实 IP 判断、网页截图识别和最终报告分析；建议选择支持多模态图片输入的模型。")
        self._ask_bool("ai", "enabled", "是否启用 AI 分析；关闭后会跳过 AI 判断、视觉识别和 AI 报告分析。")
        self._ask_text("ai", "base_url", "OpenAI 兼容服务的 Base URL；代码会请求 {base_url}/chat/completions。")
        self._ask_text("ai", "api_key", "OpenAI 兼容服务的 API Key。", secret=True)
        self._set_fixed(
            "ai",
            "api_key_header",
            "Authorization",
            "ai_client 用它构造认证请求头。",
            "OpenAI 兼容格式固定为 Authorization: Bearer <API Key>。",
        )
        self._ask_text("ai", "model", "OpenAI 兼容模型名称；url-discover 阶段会把网页截图交给模型识别，建议使用支持多模态的模型。")
        self._ask_int("ai", "timeout_seconds", "AI HTTP 请求默认超时时间。")
        self._log("AI 输入/输出上限由代码按阶段自动控制，避免用户误配导致 DNS 记录遗漏或模型请求失败。")
        self._log("")

    def _step_web_probe(self) -> None:
        self._section(9, 10, "Web 探测", "配置 classify 阶段生成 Web 入口时的 HTTP 探测参数。")
        self._ask_float("web_probe", "timeout_seconds", "HTTP/HTTPS 探测单个入口的请求超时时间。")
        self._ask_int("web_probe", "max_workers", "HTTP/HTTPS 探测并发 worker 数。")
        self._ask_int("web_probe", "max_body_bytes", "探测时最多读取的响应正文大小，用于标题和页面特征提取。")
        self._ask_int("web_probe", "max_domains_per_ip", "同一 IP 每批最多探测的域名候选数；后续运行可继续处理剩余候选。")
        self._ask_text("web_probe", "user_agent", "HTTP 探测和浏览器截图时使用的 User-Agent。")

    def _step_url_discovery(self) -> None:
        self._section(10, 10, "URL 视觉识别", "配置 Playwright 浏览器截图、页面等待和截图交给 AI 识别的规则。")
        self._ask_float("url_discovery", "timeout_seconds", "url-discover 阶段单个 URL 处理的常规超时时间。")
        self._ask_int("url_discovery", "page_hard_timeout_seconds", "Playwright 处理单个页面的硬超时时间。")
        self._ask_int("url_discovery", "ai_timeout_seconds", "截图视觉识别调用 AI 的超时时间。")
        self._ask_int("url_discovery", "visual_max_pages", "每批最多进行截图和 AI 视觉识别的页面数量；后续运行可继续处理剩余页面。")
        self._ask_text("url_discovery", "screenshot_dir", "网页截图文件保存目录。")
        self._ask_text("url_discovery", "browser_channel", "Playwright 浏览器通道；留空表示使用 Playwright 自带 Chromium。")
        self._ask_bool("url_discovery", "browser_headless", "是否以无头模式运行浏览器。")
        self._ask_choice("url_discovery", "browser_wait_until", "浏览器等待页面加载到哪个状态后截图。", ["domcontentloaded", "load", "networkidle", "commit"])
        self._ask_int("url_discovery", "browser_wait_after_load_ms", "页面达到等待状态后额外等待的毫秒数，让动态内容完成渲染。")
        self._ask_int("url_discovery", "screenshot_width", "浏览器截图视口宽度。")
        self._ask_int("url_discovery", "screenshot_height", "浏览器截图视口高度。")
        self._ask_bool("url_discovery", "screenshot_full_page", "是否截取整页；关闭时只截当前视口。")
        self._ask_choice("url_discovery", "screenshot_detail", "发送给支持视觉输入的 OpenAI 兼容模型时的图片细节级别。", ["low", "high", "auto"])
        self._ask_int_list("url_discovery", "allow_http_statuses", "哪些 HTTP 状态码会被认为可进入截图和视觉识别。")

    def _step_summary(self, config_path: Path) -> None:
        """确认并保存"""
        self._log("")
        self._log("─" * 50)
        self._log("确认配置")
        self._log("─" * 50)
        self._log("")

        enscan_configured = _configured_secret(self.config_data.get("enscan", {}).get("tycid"))
        fofa_configured = _configured_secret(self.config_data.get("fofa", {}).get("api_key"))
        ai_configured = _configured_secret(self.config_data.get("ai", {}).get("api_key"))

        self._log(f"数据库:     {self.config_data['database']['url']}")
        self._log(f"天眼查:     {'已配置' if enscan_configured else '未配置'}")
        self._log(f"FOFA:       {'已配置' if fofa_configured else '未配置'}")
        self._log(f"AI:         {'已配置' if ai_configured else '未配置'}")
        self._log(f"AI 模型:    {self.config_data['ai']['model']}")
        self._log("")

        save = questionary.confirm(
            f"是否保存配置到 {config_path}？",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()

        if save:
            self._save_config(config_path)
        else:
            self._log("配置未保存")

    def _save_config(self, config_path: Path) -> None:
        """保存配置"""
        config = AppConfig.model_validate(self.config_data)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            yaml.safe_dump(public_config_dump(config), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

        self._log("")
        self._log(f"配置已保存到: {config_path}")
        self._log("")
        self._log("下一步:")
        self._log("  · 安装外部工具: assetmap install-tools")
        self._log("  · 检查环境: assetmap env-check")
        self._log("  · 检查 AI: assetmap ai-check")
        self._log("  · 开始扫描: assetmap scan \"公司名称\"")
