from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from assetmap.config import ToolCommandConfig


def _exe_name(name: str) -> str:
    return f"{name}.exe" if platform.system().lower().startswith("windows") else name


def _windows_nmap() -> Path | None:
    for root in ("ProgramFiles", "ProgramFiles(x86)"):
        candidate = Path(os.environ.get(root, "")) / "Nmap" / "nmap.exe"
        if candidate.exists():
            return candidate
    return None


class ToolResolver:
    def __init__(self, config: ToolCommandConfig, base_dir: Path | None = None) -> None:
        self.config = config
        self.base_dir = base_dir

    def executable(self, tool_name: str) -> Path | None:
        tools_dir = Path(self.config.tools_dir)
        if self.base_dir and not tools_dir.is_absolute():
            tools_dir = self.base_dir / tools_dir
        local = tools_dir / tool_name / _exe_name(tool_name)
        if local.exists():
            return local
        if tool_name == "nmap":
            found = _windows_nmap()
            if found:
                return found
        found = shutil.which(tool_name)
        return Path(found) if found else None

    def nmap_executable(self) -> Path | None:
        return self.executable("nmap")

    def httpx_executable(self) -> Path | None:
        return self.executable("httpx")

    def check_environment(
        self,
        include_subdomain_tools: bool = True,
        include_nmap: bool = True,
        include_httpx: bool = False,
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        if include_subdomain_tools:
            for tool_name in ("subfinder", "dnsx"):
                executable = self.executable(tool_name)
                results.append(
                    {
                        "name": tool_name,
                        "ok": executable is not None,
                        "detail": str(executable) if executable else "not found in tools dir or PATH",
                        "suggestion": f"Place {tool_name}.exe under tools/{tool_name}/ or install it in PATH.",
                    }
                )
        if include_nmap:
            executable = self.nmap_executable()
            results.append(
                {
                    "name": "nmap",
                    "ok": executable is not None,
                    "detail": str(executable) if executable else "not found in tools dir, PATH, or Program Files",
                    "suggestion": "Install Nmap or put nmap.exe under tools/nmap/.",
                }
            )
        if include_httpx:
            executable = self.httpx_executable()
            results.append(
                {
                    "name": "httpx",
                    "ok": executable is not None,
                    "detail": str(executable) if executable else "not found in tools dir or PATH",
                    "suggestion": "Install ProjectDiscovery httpx or put its binary under tools/httpx/.",
                }
            )
        return results
