from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from pathlib import Path
from typing import Any

from assetmap.config import AppConfig
from assetmap.services.runtime.tool_resolver import ToolResolver


PYTHON_IMPORTS = {
    "dnspython": "dns",
    "httpx": "httpx",
    "openpyxl": "openpyxl",
    "python-docx": "docx",
    "PyYAML": "yaml",
    "sqlmodel": "sqlmodel",
    "typer": "typer",
}


class EnvironmentCheckService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def check(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        results.extend(self._python_imports())
        results.extend(self._optional_python_imports())
        results.extend(self._external_tools())
        results.extend(self._browser())
        results.extend(self._files())
        results.extend(self._configuration())
        return results

    def _python_imports(self) -> list[dict[str, Any]]:
        return [
            self._result(
                f"python:{name}",
                importlib.util.find_spec(module) is not None,
                "installed" if importlib.util.find_spec(module) is not None else "not importable",
                f"Install project dependencies: pip install -e .[dev] (missing {name}).",
            )
            for name, module in PYTHON_IMPORTS.items()
        ]

    def _optional_python_imports(self) -> list[dict[str, Any]]:
        playwright_installed = _module_available("playwright.sync_api")
        return [
            self._result(
                "python:playwright",
                True,
                "installed" if playwright_installed else "optional; URL screenshots will be skipped",
                "Install visual dependency when screenshots are needed: pip install -e .[visual].",
            )
        ]

    def _external_tools(self) -> list[dict[str, Any]]:
        resolver = ToolResolver(self.config.tools, self.config.config_dir)
        results = resolver.check_environment(include_httpx=True)
        return results

    def _browser(self) -> list[dict[str, Any]]:
        if not _module_available("playwright.sync_api"):
            return [
                self._result(
                    "browser:playwright",
                    False,
                    "playwright not installed",
                    "Install visual dependency: pip install -e .[visual] && playwright install chromium",
                )
            ]
        # 检查 Playwright Chromium 是否已安装
        chromium_installed = self._check_playwright_chromium()
        if chromium_installed:
            return [
                self._result(
                    "browser:playwright-chromium",
                    True,
                    "Playwright Chromium installed",
                    "",
                )
            ]
        return [
            self._result(
                "browser:playwright-chromium",
                False,
                "Playwright Chromium not installed",
                "Run: playwright install chromium",
            )
        ]

    def _check_playwright_chromium(self) -> bool:
        """检查 Playwright Chromium 是否已安装"""
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                # 尝试获取 Chromium 可执行文件路径
                browser_type = p.chromium
                # 检查浏览器是否可执行（通过检查路径）
                import subprocess
                result = subprocess.run(
                    ["playwright", "install", "--dry-run", "chromium"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # 如果命令成功且输出包含 "already installed" 或类似信息
                return result.returncode == 0
        except Exception:
            # 备用方案：检查常见安装路径
            return self._check_playwright_chromium_path()

    def _check_playwright_chromium_path(self) -> bool:
        """通过文件系统检查 Playwright Chromium 是否已安装"""
        import platform
        from pathlib import Path

        system = platform.system().lower()
        if system == "darwin":
            # macOS: ~/Library/Caches/ms-playwright/
            cache_dir = Path.home() / "Library" / "Caches" / "ms-playwright"
        elif system == "windows":
            # Windows: %LOCALAPPDATA%\ms-playwright
            import os
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            cache_dir = Path(local_app_data) / "ms-playwright" if local_app_data else Path()
        else:
            # Linux: ~/.cache/ms-playwright
            cache_dir = Path.home() / ".cache" / "ms-playwright"

        if not cache_dir.exists():
            return False

        # 检查是否有 chromium 目录
        for item in cache_dir.iterdir():
            if item.is_dir() and "chromium" in item.name.lower():
                return True
        return False

    def _files(self) -> list[dict[str, Any]]:
        checks = [
            (
                "domain_mapping.dnsx_wordlist",
                self.config.resolve_path(self.config.domain_mapping.dnsx_wordlist),
                "Place a subdomain wordlist at domain_mapping.dnsx_wordlist or update config.yaml.",
            ),
            (
                "domain_mapping.subfinder_provider_config",
                self.config.resolve_path(self.config.domain_mapping.subfinder_provider_config),
                "Copy config/subfinder/provider-config.example.yaml to the configured path and add provider keys.",
            ),
        ]
        return [
            self._result(name, path.exists(), str(path) if path.exists() else f"missing: {path}", suggestion)
            for name, path, suggestion in checks
        ]

    def _configuration(self) -> list[dict[str, Any]]:
        results = [
            self._result(
                "enterprise_discovery.tycid",
                _configured_secret(self.config.enterprise_discovery.tycid),
                "configured" if _configured_secret(self.config.enterprise_discovery.tycid) else "missing or placeholder",
                "Set enterprise_discovery.tycid in config.yaml.",
            ),
            self._result(
                "enterprise_discovery.auth_token",
                _configured_secret(self.config.enterprise_discovery.auth_token),
                "configured" if _configured_secret(self.config.enterprise_discovery.auth_token) else "missing or placeholder",
                "Set enterprise_discovery.auth_token in config.yaml.",
            ),
        ]
        if self.config.ai.enabled:
            results.append(
                self._result(
                    "ai.api_key",
                    _configured_secret(self.config.ai.api_key),
                    f"enabled model={self.config.ai.model}" if _configured_secret(self.config.ai.api_key) else "enabled but missing or placeholder",
                    "Set ai.api_key in config.yaml or disable ai.enabled.",
                )
            )
        else:
            results.append(self._result("ai", True, "disabled", ""))
        fofa_ok = _configured_secret(self.config.fofa.email) and _configured_secret(self.config.fofa.api_key)
        results.append(
            self._result(
                "fofa.credentials",
                fofa_ok,
                "configured" if fofa_ok else "missing or placeholder",
                "Set fofa.email and fofa.api_key in config.yaml.",
            )
        )
        return results

    def _result(self, name: str, ok: bool, detail: str, suggestion: str) -> dict[str, Any]:
        return {"name": name, "ok": ok, "detail": detail, "suggestion": suggestion}


def _configured_secret(value: str | None) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    upper = text.upper()
    return not (upper.startswith("YOUR_") or upper in {"CHANGE_ME", "TODO", "NONE", "NULL"})


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False
