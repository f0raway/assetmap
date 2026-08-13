from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator


DEFAULT_CONFIG_PATH = Path("config.yaml")
DEFAULT_CONFIG_TEMPLATE_PATH = Path(__file__).with_name("config.template.yaml")
DEFAULT_TOOLS_DIR = "tools"
HTTPX_THREADS = 30
HTTPX_RATE_LIMIT = 100
PUBLIC_CONFIG_EXCLUDE = {
    "tools": {
        "httpx_command",
    },
    "ai": {
        "max_dns_records",
        "max_prompt_chars",
        "max_completion_tokens",
    }
}


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///data/assetmap.db"


class ToolCommandConfig(BaseModel):
    nmap_command: str = (
        "{binary} -Pn -p- --open -sV --version-intensity 5 "
        "--min-hostgroup 16 --min-rate 500 --initial-rtt-timeout 300ms "
        "--max-rtt-timeout 2000ms --min-rtt-timeout 100ms --defeat-rst-ratelimit "
        "--max-retries 2 --script-timeout 60s -iL {targets_file} -oX {xml_output} -oN {normal_output}"
    )
    httpx_command: str = (
        "{binary} -l {input_file} -json -silent -sc -title -td -server -ct -cl "
        "-favicon -hash sha256 -ip -cname -asn -cdn -fr -nfs -timeout {timeout} "
        f"-retries 1 -t {HTTPX_THREADS} -rl {HTTPX_RATE_LIMIT} -random-agent=false -H {{user_agent_header}} "
        "-stats -si 15"
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_nmap_batch_command(cls, value):
        """Use the historical batch template when loading an older config file."""
        if not isinstance(value, dict):
            return value
        migrated = dict(value)
        # httpx behaviour is maintained by the program so that service
        # checkpoints and real-time terminal output always have one format.
        migrated.pop("httpx_command", None)
        if migrated.get("nmap_batch_command"):
            migrated["nmap_command"] = migrated["nmap_batch_command"]
        return migrated

    @property
    def tools_dir(self) -> str:
        """Fixed local tool directory; it is not a user-facing stage setting."""
        return DEFAULT_TOOLS_DIR

    @field_validator("nmap_command", "httpx_command")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class DomainMappingConfig(BaseModel):
    """The only user-managed settings for the domain mapping stage."""

    subfinder_provider_config: str = "config/subfinder/provider-config.yaml"
    dnsx_wordlist: str = "data/wordlists/Subdomain.txt"

    @field_validator("subfinder_provider_config", "dnsx_wordlist")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class FofaConfig(BaseModel):
    email: str = "YOUR_FOFA_EMAIL"
    api_key: str = "YOUR_FOFA_API_KEY"

    @field_validator("email", "api_key")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class EnterpriseDiscoveryConfig(BaseModel):
    """The only user-managed settings for enterprise discovery."""

    tycid: str = "YOUR_TYCID"
    auth_token: str = "YOUR_TYC_AUTH_TOKEN"
    control_threshold: float = Field(default=0.47, ge=0, le=1)
    max_depth: int = Field(default=10, ge=0)

    @field_validator("tycid", "auth_token")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()


class WebProbeConfig(BaseModel):
    timeout_seconds: float = 8
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )


class UrlDiscoveryConfig(BaseModel):
    """User-facing limits for serial rendered-HTML Web identification."""

    timeout_seconds: float = 15
    page_hard_timeout_seconds: int = 60
    ai_timeout_seconds: int = 240


class AiConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.openai.com/v1"
    api_key: str = "YOUR_OPENAI_API_KEY"
    api_key_header: str = "Authorization"
    model: str = "gpt-4o"
    timeout_seconds: int = 240
    max_dns_records: int = 5000
    max_prompt_chars: int = 120000
    max_completion_tokens: int = 8192

    @field_validator("base_url", "api_key", "api_key_header", "model")
    @classmethod
    def strip_text_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("max_completion_tokens")
    @classmethod
    def clamp_max_completion_tokens(cls, value: int) -> int:
        return min(max(value, 256), 8192)


class AppConfig(BaseModel):
    _config_path: Path = PrivateAttr(default=DEFAULT_CONFIG_PATH)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    enterprise_discovery: EnterpriseDiscoveryConfig = Field(default_factory=EnterpriseDiscoveryConfig)
    domain_mapping: DomainMappingConfig = Field(default_factory=DomainMappingConfig)
    tools: ToolCommandConfig = Field(default_factory=ToolCommandConfig)
    fofa: FofaConfig = Field(default_factory=FofaConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    web_probe: WebProbeConfig = Field(default_factory=WebProbeConfig)
    url_discovery: UrlDiscoveryConfig = Field(default_factory=UrlDiscoveryConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_enterprise_discovery_config(cls, value):
        """Read older ``org`` / ``enscan`` files without preserving their old shape."""
        if not isinstance(value, dict):
            return value
        migrated = dict(value)
        current = dict(migrated.get("enterprise_discovery") or {})
        legacy_enscan = migrated.get("enscan") if isinstance(migrated.get("enscan"), dict) else {}
        legacy_org = migrated.get("org") if isinstance(migrated.get("org"), dict) else {}
        for name, source in (
            ("tycid", legacy_enscan),
            ("auth_token", legacy_enscan),
            ("control_threshold", legacy_org),
            ("max_depth", legacy_org),
        ):
            if name not in current and name in source:
                current[name] = source[name]
        migrated["enterprise_discovery"] = current
        domain_mapping = dict(migrated.get("domain_mapping") or {})
        legacy_tools = migrated.get("tools") if isinstance(migrated.get("tools"), dict) else {}
        if "dnsx_wordlist" not in domain_mapping and legacy_tools.get("wordlist"):
            domain_mapping["dnsx_wordlist"] = legacy_tools["wordlist"]
        migrated["domain_mapping"] = domain_mapping
        return migrated

    def bind_config_path(self, path: Path) -> "AppConfig":
        self._config_path = path.expanduser().resolve()
        return self

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def config_dir(self) -> Path:
        return self._config_path.parent

    def resolve_path(self, value: Path | str) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.config_dir / path

    def data_path(self, *parts: str) -> Path:
        return self.resolve_path("data").joinpath(*parts)

    @property
    def database_url(self) -> str:
        prefix = "sqlite:///"
        if not self.database.url.startswith(prefix):
            return self.database.url
        db_path = Path(self.database.url[len(prefix) :]).expanduser()
        if db_path.is_absolute():
            return self.database.url
        return f"{prefix}{self.resolve_path(db_path)}"


def resolve_config_path(path: Path | str = DEFAULT_CONFIG_PATH) -> Path:
    """Resolve the default config from the repository root, not a package subdirectory."""
    requested = Path(path).expanduser()
    if requested.is_absolute() or requested != DEFAULT_CONFIG_PATH:
        return requested.resolve()
    current = Path.cwd().resolve()
    for directory in (current, *current.parents):
        if (directory / "pyproject.toml").exists() and (directory / "config.yaml").exists():
            return directory / "config.yaml"
    return current / requested


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> AppConfig:
    file_path = resolve_config_path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(data).bind_config_path(file_path)


def public_config_dump(config: AppConfig) -> dict:
    """Return the user-facing config shape written to config.yaml."""
    return config.model_dump(mode="json", exclude=PUBLIC_CONFIG_EXCLUDE)


def write_sample_config(path: Path | str = DEFAULT_CONFIG_PATH, overwrite: bool = True) -> Path:
    file_path = resolve_config_path(path)
    if file_path.exists() and not overwrite:
        return file_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(DEFAULT_CONFIG_TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return file_path
