from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


DEFAULT_CONFIG_PATH = Path("config.yaml")
PUBLIC_CONFIG_EXCLUDE = {
    "ai": {
        "max_dns_records",
        "max_prompt_chars",
        "max_completion_tokens",
    }
}


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///data/assetmap.db"


class OrgConfig(BaseModel):
    control_threshold: float = 0.5
    max_depth: int = 10


class ToolCommandConfig(BaseModel):
    tools_dir: str = "tools"
    subdomain_tools_enabled: list[str] = Field(default_factory=lambda: ["subfinder", "dnsx"])
    subdomain_tool_timeout_seconds: int = 300
    subdomain_tool_max_output_lines: int = 10000
    subfinder_command: str = "{binary} -d {domain} -silent -all -o {output}"
    dnsx_command: str = "{binary} -silent -d {domain} -w {wordlist} -o {output} -t 100 -retry 2 -rl 300 -wt 5 -duc -nc"
    wordlist: str = "data/wordlists/Subdomain.txt"
    nmap_command: str = (
        "{binary} -Pn --top-ports 100 --open -sV --version-intensity 2 "
        "--min-hostgroup 24 --min-rate 800 --initial-rtt-timeout 300ms "
        "--max-rtt-timeout 2000ms --min-rtt-timeout 100ms --defeat-rst-ratelimit "
        "--max-retries 2 --host-timeout 1800s {target} -oX {xml_output} -oN {normal_output}"
    )
    nmap_mode: str = "batch"
    nmap_batch_command: str = (
        "{binary} -Pn --top-ports 100 --open -sV --version-intensity 2 "
        "--min-hostgroup 24 --min-rate 800 --initial-rtt-timeout 300ms "
        "--max-rtt-timeout 2000ms --min-rtt-timeout 100ms --defeat-rst-ratelimit "
        "--max-retries 2 --host-timeout 1800s -iL {targets_file} -oX {xml_output} -oN {normal_output}"
    )
    nmap_max_workers: int = 3
    nmap_timeout_seconds: int = 600
    nmap_service_detect_command: str = "{binary} -Pn -sV --version-intensity 5 -p {ports} {target} -oX {xml_output} -oN {normal_output}"

    @field_validator("tools_dir", "subfinder_command", "dnsx_command", "wordlist", "nmap_command", "nmap_mode", "nmap_batch_command", "nmap_service_detect_command")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class PortScanConfig(BaseModel):
    sources_enabled: list[str] = Field(default_factory=lambda: ["nmap"])
    target_sources_enabled: list[str] = Field(default_factory=lambda: ["ai", "manual", "dns_public"])


class FofaConfig(BaseModel):
    base_url: str = "https://fofa.info"
    email: str = "YOUR_FOFA_EMAIL"
    api_key: str = "YOUR_FOFA_API_KEY"
    fields: str = "host,ip,port,protocol,title,server"
    size: int = 100
    full: bool = False
    timeout_seconds: int = 30

    @field_validator("base_url", "email", "api_key")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class EnscanConfig(BaseModel):
    script: str = "assetmap/collectors/tyc_invest_crawler.py"
    output_dir: str = "data/enscan"
    timeout_seconds: int = 1800
    tycid: str = "YOUR_TYCID"
    auth_token: str = "YOUR_TYC_AUTH_TOKEN"
    request_delay_seconds: float = 1.0
    request_timeout_seconds: int = 20
    asset_workers: int = 1
    verbose: bool = False

    @field_validator("script", "output_dir", "tycid", "auth_token")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class WebProbeConfig(BaseModel):
    timeout_seconds: float = 8
    max_workers: int = 20
    max_body_bytes: int = 262144
    max_domains_per_ip: int = 80
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )


class UrlDiscoveryConfig(BaseModel):
    timeout_seconds: float = 15
    page_hard_timeout_seconds: int = 60
    ai_timeout_seconds: int = 90
    visual_max_pages: int = 50
    screenshot_dir: str = "data/screenshots"
    browser_channel: str = ""  # 空字符串表示使用 Playwright 自带 Chromium
    browser_headless: bool = True
    browser_wait_until: str = "domcontentloaded"
    browser_wait_after_load_ms: int = 1500
    screenshot_width: int = 1365
    screenshot_height: int = 900
    screenshot_full_page: bool = False
    screenshot_detail: str = "low"
    allow_http_statuses: list[int] = Field(default_factory=lambda: [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403])


class DnsConfig(BaseModel):
    timeout_seconds: float = 5
    lifetime_seconds: float = 8
    nameservers: list[str] = Field(default_factory=list)
    max_workers: int = 20

    @field_validator("lifetime_seconds")
    @classmethod
    def clamp_lifetime_seconds(cls, value: float) -> float:
        return min(max(value, 1.0), 60.0)

    @field_validator("nameservers")
    @classmethod
    def strip_nameservers(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item.strip()]


class AiConfig(BaseModel):
    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    api_key: str = "YOUR_OPENAI_API_KEY"
    api_key_header: str = "Authorization"
    model: str = "gpt-4o"
    timeout_seconds: int = 120
    max_dns_records: int = 2000
    max_prompt_chars: int = 60000
    max_completion_tokens: int = 4096

    @field_validator("base_url", "api_key", "api_key_header", "model")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("max_completion_tokens")
    @classmethod
    def clamp_max_completion_tokens(cls, value: int) -> int:
        return min(max(value, 256), 8192)


class AppConfig(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    org: OrgConfig = Field(default_factory=OrgConfig)
    tools: ToolCommandConfig = Field(default_factory=ToolCommandConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    fofa: FofaConfig = Field(default_factory=FofaConfig)
    enscan: EnscanConfig = Field(default_factory=EnscanConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    web_probe: WebProbeConfig = Field(default_factory=WebProbeConfig)
    url_discovery: UrlDiscoveryConfig = Field(default_factory=UrlDiscoveryConfig)


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> AppConfig:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(data)


def public_config_dump(config: AppConfig) -> dict:
    """Return the user-facing config shape written to config.yaml."""
    return config.model_dump(mode="json", exclude=PUBLIC_CONFIG_EXCLUDE)


def write_sample_config(path: Path | str = DEFAULT_CONFIG_PATH, overwrite: bool = True) -> Path:
    file_path = Path(path)
    if file_path.exists() and not overwrite:
        return file_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    content = public_config_dump(AppConfig())
    file_path.write_text(
        yaml.safe_dump(content, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return file_path
