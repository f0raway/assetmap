"""TUI 配置向导服务"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import questionary
import yaml
from questionary import Style

from assetmap.config import AppConfig, DEFAULT_CONFIG_PATH, load_config, public_config_dump
from assetmap.services.runtime.environment import _configured_secret


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
        self._step_enterprise_discovery()
        self._step_domain_mapping()
        self._step_tools()
        self._step_fofa()
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
        self._section(1, 9, "数据库", "配置本地任务、资产、报告等数据的存储位置。")
        self._ask_text("database", "url", "create_db_and_engine 会使用它连接 SQLite；默认写入 data/assetmap.db。")

    def _step_enterprise_discovery(self) -> None:
        self._section(2, 9, "企业发现", "配置天眼查凭证与企业股权穿透边界；其余采集策略由程序固定管理。")
        self._ask_text("enterprise_discovery", "tycid", "天眼查 TYCID；未配置会阻止企业发现阶段运行。", secret=True)
        self._ask_text("enterprise_discovery", "auth_token", "天眼查授权 Token；未配置会阻止企业发现阶段运行。", secret=True)
        self._ask_float("enterprise_discovery", "control_threshold", "纳入追踪的最低持股比例；0.47 表示持股比例大于或等于 47%。")
        self._ask_int("enterprise_discovery", "max_depth", "从目标企业（第 0 层）开始允许向下展开的最大层级；0 表示不限制层级。")

    def _step_tools(self) -> None:
        self._section(4, 8, "端口发现", "Nmap、FOFA 固定串行运行；这里只配置主扫描命令。")
        self._ask_text("tools", "nmap_command", "批量主动端口扫描命令模板，必须包含 -sV；支持 {binary}/{targets_file}/{xml_output}/{normal_output}。")

    def _step_domain_mapping(self) -> None:
        self._section(3, 8, "域名测绘", "subfinder 与 dnsx 固定串行运行；DNS 解析结果会严格过滤非源站地址。")
        self._ask_text("domain_mapping", "subfinder_provider_config", "subfinder 的 provider Key 文件路径；文件内容不会写入本配置。")
        self._ask_text("domain_mapping", "dnsx_wordlist", "dnsx 子域名字典路径；env-check 会检查该文件。")

    def _step_fofa(self) -> None:
        self._section(5, 8, "FOFA", "配置 FOFA 凭证；检索字段和请求策略由程序固定管理。")
        self._ask_text("fofa", "email", "FOFA API 账号邮箱；启用 fofa 数据源时必须配置。")
        self._ask_text("fofa", "api_key", "FOFA API Key；启用 fofa 数据源时必须配置。", secret=True)

    def _step_ai(self) -> None:
        self._section(6, 8, "AI", "仅配置 OpenAI 兼容接口。AI 用于 DNS 真实 IP 判断、网页渲染 HTML 识别和最终报告分析；普通文本模型即可使用。")
        self._ask_bool("ai", "enabled", "是否启用 AI 分析；关闭后会跳过 AI 判断、Web 页面识别和 AI 报告分析。")
        self._ask_text("ai", "base_url", "OpenAI 兼容服务的 Base URL；代码会请求 {base_url}/chat/completions。")
        self._ask_text("ai", "api_key", "OpenAI 兼容服务的 API Key。", secret=True)
        self._set_fixed(
            "ai",
            "api_key_header",
            "Authorization",
            "ai_client 用它构造认证请求头。",
            "OpenAI 兼容格式固定为 Authorization: Bearer <API Key>。",
        )
        self._ask_text("ai", "model", "OpenAI 兼容模型名称；url-discover 阶段会分析浏览器加载后的 HTML 和可见文本，不要求图片输入能力。")
        self._ask_int("ai", "timeout_seconds", "AI HTTP 请求默认超时时间。")
        self._log("AI 输入/输出上限由代码按阶段自动控制，避免用户误配导致 DNS 记录遗漏或模型请求失败。")
        self._log("")

    def _step_web_probe(self) -> None:
        self._section(7, 8, "Web 探测", "ProjectDiscovery httpx 识别所有候选 Web 服务；这里仅保留请求超时和浏览器 UA。")
        self._ask_float("web_probe", "timeout_seconds", "httpx 探测单个入口的请求超时时间。")
        self._ask_text("web_probe", "user_agent", "httpx 探测和浏览器页面加载共用的 Chrome User-Agent。")

    def _step_url_discovery(self) -> None:
        self._section(8, 8, "Web 页面识别", "所有待处理页面固定串行加载，保存渲染后的 HTML 并交给 AI 文本识别；不设页面总量上限。")
        self._ask_float("url_discovery", "timeout_seconds", "单个 URL 的常规打开超时时间。")
        self._ask_int("url_discovery", "page_hard_timeout_seconds", "Playwright 处理单个页面的硬超时时间。")
        self._ask_int("url_discovery", "ai_timeout_seconds", "HTML 文本识别调用 AI 的超时时间。")
        self._log("浏览器加载策略、HTML 截断长度和可识别状态码由程序固定管理，避免误配。")

    def _step_summary(self, config_path: Path) -> None:
        """确认并保存"""
        self._log("")
        self._log("─" * 50)
        self._log("确认配置")
        self._log("─" * 50)
        self._log("")

        enterprise_discovery_configured = _configured_secret(self.config_data.get("enterprise_discovery", {}).get("tycid"))
        fofa_configured = _configured_secret(self.config_data.get("fofa", {}).get("api_key"))
        ai_configured = _configured_secret(self.config_data.get("ai", {}).get("api_key"))

        self._log(f"数据库:     {self.config_data['database']['url']}")
        self._log(f"天眼查:     {'已配置' if enterprise_discovery_configured else '未配置'}")
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
