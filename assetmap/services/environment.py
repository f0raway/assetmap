from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from pathlib import Path
from typing import Any

from assetmap.config import AppConfig
from assetmap.services.tool_resolver import ToolResolver


PYTHON_IMPORTS = {
    "dnspython": "dns",
    "httpx": "httpx",
    "openpyxl": "openpyxl",
    "python-docx": "docx",
    "PyYAML": "yaml",
    "playwright": "playwright.sync_api",
    "sqlmodel": "sqlmodel",
    "typer": "typer",
}


class EnvironmentCheckService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def check(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        results.extend(self._python_imports())
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

    def _external_tools(self) -> list[dict[str, Any]]:
        resolver = ToolResolver(self.config.tools)
        results = resolver.check_environment()
        sources = {source.lower().strip() for source in self.config.port_scan.sources_enabled if source.strip()}
        if "nmap" not in sources:
            results = [row for row in results if row.get("name") != "nmap"]
        return results

    def _browser(self) -> list[dict[str, Any]]:
        channel = (self.config.url_discovery.browser_channel or "").lower().strip()
        if channel != "chrome":
            return [
                self._result(
                    "browser",
                    True,
                    f"using Playwright bundled browser/channel: {self.config.url_discovery.browser_channel}",
                    "",
                )
            ]
        chrome = self._chrome_path()
        return [
            self._result(
                "browser:chrome",
                chrome is not None,
                str(chrome) if chrome else "Chrome not found in PATH or common install locations",
                "Install Chrome, or set url_discovery.browser_channel to a Playwright bundled browser channel.",
            )
        ]

    def _files(self) -> list[dict[str, Any]]:
        checks = [
            (
                "enscan.script",
                Path(self.config.enscan.script),
                "Ensure assetmap/collectors/tyc_invest_crawler.py exists.",
            ),
            (
                "tools.wordlist",
                Path(self.config.tools.wordlist),
                "Place a subdomain wordlist at tools.wordlist or update config.yaml.",
            ),
        ]
        return [
            self._result(name, path.exists(), str(path) if path.exists() else f"missing: {path}", suggestion)
            for name, path, suggestion in checks
        ]

    def _configuration(self) -> list[dict[str, Any]]:
        results = [
            self._result(
                "enscan.tycid",
                _configured_secret(self.config.enscan.tycid),
                "configured" if _configured_secret(self.config.enscan.tycid) else "missing or placeholder",
                "Set enscan.tycid in config.yaml.",
            ),
            self._result(
                "enscan.auth_token",
                _configured_secret(self.config.enscan.auth_token),
                "configured" if _configured_secret(self.config.enscan.auth_token) else "missing or placeholder",
                "Set enscan.auth_token in config.yaml.",
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
        sources = {source.lower().strip() for source in self.config.port_scan.sources_enabled if source.strip()}
        if "fofa" in sources:
            fofa_ok = _configured_secret(self.config.fofa.email) and _configured_secret(self.config.fofa.api_key)
            results.append(
                self._result(
                    "fofa.credentials",
                    fofa_ok,
                    "configured" if fofa_ok else "enabled but missing or placeholder",
                    "Set fofa.email and fofa.api_key in config.yaml, or remove fofa from port_scan.sources_enabled.",
                )
            )
        else:
            results.append(self._result("fofa", True, "disabled", ""))
        return results

    def _result(self, name: str, ok: bool, detail: str, suggestion: str) -> dict[str, Any]:
        return {"name": name, "ok": ok, "detail": detail, "suggestion": suggestion}

    def _chrome_path(self) -> Path | None:
        for name in ("chrome", "chrome.exe", "Google Chrome"):
            found = shutil.which(name)
            if found:
                return Path(found)
        if platform.system().lower().startswith("windows"):
            for root in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
                base = Path(os.environ.get(root, ""))
                for relative in (
                    Path("Google/Chrome/Application/chrome.exe"),
                    Path("Google/Chrome Beta/Application/chrome.exe"),
                ):
                    candidate = base / relative
                    if candidate.exists():
                        return candidate
        return None


def _configured_secret(value: str | None) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    upper = text.upper()
    return not (upper.startswith("YOUR_") or upper in {"CHANGE_ME", "TODO", "NONE", "NULL"})
