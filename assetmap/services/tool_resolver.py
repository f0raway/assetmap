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
    def __init__(self, config: ToolCommandConfig) -> None:
        self.config = config

    def executable(self, tool_name: str) -> Path | None:
        local = Path(self.config.tools_dir) / tool_name / _exe_name(tool_name)
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

    def check_environment(
        self,
        include_subdomain_tools: bool = True,
        include_nmap: bool = True,
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        if include_subdomain_tools:
            for tool_name in self.config.subdomain_tools_enabled:
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
        return results
