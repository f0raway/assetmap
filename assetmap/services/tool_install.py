"""外部工具安装服务"""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

import httpx
from questionary import Style


CUSTOM_STYLE = Style([
    ("qmark", "fg:cyan bold"),
    ("question", "bold"),
    ("answer", "fg:green bold"),
    ("pointer", "fg:cyan bold"),
])


# 工具下载配置
TOOL_DOWNLOADS = {
    "subfinder": {
        "repo": "projectdiscovery/subfinder",
        "tag": "v2.6.8",
        "version": "2.6.8",
        "url_template": "https://github.com/projectdiscovery/subfinder/releases/download/{tag}/subfinder_{version}_{platform}.zip",
        "platforms": {
            "darwin_arm64": "macOS_arm64",
            "darwin_amd64": "macOS_amd64",
            "linux_amd64": "linux_amd64",
            "linux_arm64": "linux_arm64",
            "windows_amd64": "windows_amd64",
        },
        "extract": "subfinder",
    },
    "dnsx": {
        "repo": "projectdiscovery/dnsx",
        "tag": "v1.2.2",
        "version": "1.2.2",
        "url_template": "https://github.com/projectdiscovery/dnsx/releases/download/{tag}/dnsx_{version}_{platform}.zip",
        "platforms": {
            "darwin_arm64": "macOS_arm64",
            "darwin_amd64": "macOS_amd64",
            "linux_amd64": "linux_amd64",
            "linux_arm64": "linux_arm64",
            "windows_amd64": "windows_amd64",
        },
        "extract": "dnsx",
    },
}


class ToolInstallService:
    """外部工具安装服务"""

    def __init__(self, tools_dir: Path = Path("tools"), progress: Callable[[str], None] | None = None) -> None:
        self.tools_dir = tools_dir
        self.progress = progress

    def _log(self, message: str) -> None:
        if self.progress:
            try:
                self.progress(message)
            except OSError:
                self.progress = None

    def detect_platform(self) -> dict[str, str]:
        """检测系统平台"""
        system = platform.system().lower()
        machine = platform.machine().lower()

        # 映射到工具发布平台的命名
        arch_map = {
            ("darwin", "arm64"): "darwin_arm64",
            ("darwin", "x86_64"): "darwin_amd64",
            ("linux", "x86_64"): "linux_amd64",
            ("linux", "aarch64"): "linux_arm64",
            ("windows", "amd64"): "windows_amd64",
        }

        arch = arch_map.get((system, machine), "unknown")

        return {
            "system": system,
            "machine": machine,
            "arch": arch,
            "is_windows": system == "windows",
        }

    def run(self, tools: list[str] | None = None) -> bool:
        """运行安装向导"""
        platform_info = self.detect_platform()

        self._log("")
        self._log("=" * 50)
        self._log("  安装外部工具")
        self._log("=" * 50)
        self._log("")
        self._log(f"检测到系统: {platform_info['system'].title()} ({platform_info['machine']})")
        self._log("")

        if not tools:
            tools = ["subfinder", "dnsx", "nmap"]

        success_count = 0
        for tool_name in tools:
            if tool_name == "nmap":
                if self._install_nmap(platform_info):
                    success_count += 1
            elif tool_name in TOOL_DOWNLOADS:
                if self._install_tool(tool_name, platform_info):
                    success_count += 1
            else:
                self._log(f"✗ 未知工具: {tool_name}")

        self._log("")
        if success_count == len(tools):
            self._log("✓ 所有工具安装完成!")
        else:
            self._log(f"○ 安装完成: {success_count}/{len(tools)}")
            self._log("  运行 `assetmap env-check` 验证安装")

        return success_count == len(tools)

    def _install_tool(self, tool_name: str, platform_info: dict[str, str]) -> bool:
        """安装单个工具"""
        config = TOOL_DOWNLOADS[tool_name]
        arch = platform_info["arch"]

        platform_name = config["platforms"].get(arch)
        if arch == "unknown" or not platform_name:
            self._log(f"✗ {tool_name}: 不支持的平台 {platform_info['system']}/{platform_info['machine']}")
            return False

        self._log(f"[{tool_name}]")

        # 构造下载 URL
        url = self._download_url(config, platform_name)

        self._log(f"  下载: {url}")

        # 下载文件
        try:
            temp_file = self._download_file(url)
            if not temp_file:
                self._log(f"  ✗ 下载失败")
                return False
        except Exception as e:
            self._log(f"  ✗ 下载失败: {e}")
            return False

        # 解压到 tools 目录
        tool_dir = self.tools_dir / tool_name
        tool_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._extract_archive(temp_file, tool_dir, config["extract"], platform_info["is_windows"])
            self._log(f"  ✓ 安装成功: {config['version']}")
            return True
        except Exception as e:
            self._log(f"  ✗ 解压失败: {e}")
            return False
        finally:
            # 清理临时文件
            if temp_file.exists():
                temp_file.unlink()

    def _download_url(self, config: dict[str, Any], platform_name: str) -> str:
        return config["url_template"].format(
            tag=config["tag"],
            version=config["version"],
            platform=platform_name,
        )

    def _download_file(self, url: str) -> Path | None:
        """下载文件"""
        temp_handle = tempfile.NamedTemporaryFile(prefix="assetmap_download_", suffix=".zip", delete=False)
        temp_file = Path(temp_handle.name)

        try:
            with temp_handle as f, httpx.stream("GET", url, follow_redirects=True, timeout=60) as response:
                if response.status_code != 200:
                    temp_file.unlink(missing_ok=True)
                    return None

                total = int(response.headers.get("content-length", 0))
                downloaded = 0

                for chunk in response.iter_bytes(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)

                    # 显示进度
                    if total > 0:
                        percent = downloaded * 100 // total
                        bar = "█" * (percent // 5) + "░" * (20 - percent // 5)
                        self._log(f"  进度: {bar} {percent}%")

            return temp_file
        except Exception:
            temp_file.unlink(missing_ok=True)
            return None

    def _extract_archive(
        self,
        archive_path: Path,
        target_dir: Path,
        extract_name: str,
        is_windows: bool,
    ) -> None:
        """解压归档文件"""
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(target_dir)
            self._normalize_executable(target_dir, extract_name, is_windows)

    def _normalize_executable(self, target_dir: Path, extract_name: str, is_windows: bool) -> None:
        """把不同压缩包里的二进制文件统一放到 ToolResolver 期望的位置。"""
        expected_name = f"{extract_name}.exe" if is_windows else extract_name
        expected = target_dir / expected_name
        candidates = [
            target_dir / expected_name,
            target_dir / extract_name,
            target_dir / f"{extract_name}.exe",
            target_dir / extract_name.capitalize(),
            target_dir / f"{extract_name.capitalize()}.exe",
        ]
        candidates.extend(
            path
            for path in target_dir.rglob("*")
            if path.is_file() and path.name.lower() in {extract_name, f"{extract_name}.exe"}
        )

        source = next((path for path in candidates if path.exists() and path.is_file()), None)
        if source is None:
            raise FileNotFoundError(f"未在压缩包中找到可执行文件: {extract_name}")

        if source != expected:
            if expected.exists():
                expected.unlink()
            shutil.copy2(source, expected)
        if not is_windows:
            expected.chmod(0o755)

    def _install_nmap(self, platform_info: dict[str, str]) -> bool:
        """安装 nmap"""
        self._log("[nmap]")

        system = platform_info["system"]

        if system == "darwin":
            # macOS: 使用 Homebrew
            if not shutil.which("brew"):
                self._log("  ✗ 未检测到 Homebrew")
                self._log("  请先安装 Homebrew: https://brew.sh/")
                return False

            self._log("  执行: brew install nmap")
            try:
                subprocess.run(["brew", "install", "nmap"], check=True, capture_output=True)
                self._log("  ✓ 安装成功")
                return True
            except subprocess.CalledProcessError as e:
                self._log(f"  ✗ 安装失败: {e.stderr.decode()}")
                return False

        elif system == "linux":
            # Linux: 使用包管理器
            if shutil.which("apt"):
                self._log("  执行: sudo apt install nmap")
                try:
                    subprocess.run(["sudo", "apt", "install", "-y", "nmap"], check=True)
                    self._log("  ✓ 安装成功")
                    return True
                except subprocess.CalledProcessError as e:
                    self._log(f"  ✗ 安装失败")
                    return False
            elif shutil.which("yum"):
                self._log("  执行: sudo yum install nmap")
                try:
                    subprocess.run(["sudo", "yum", "install", "-y", "nmap"], check=True)
                    self._log("  ✓ 安装成功")
                    return True
                except subprocess.CalledProcessError:
                    self._log(f"  ✗ 安装失败")
                    return False
            else:
                self._log("  ✗ 未检测到支持的包管理器")
                self._log("  请手动安装: https://nmap.org/download.html")
                return False

        elif system == "windows":
            # Windows: 提示下载安装
            self._log("  请下载安装包: https://nmap.org/download.html")
            self._log("  或运行: tools/nmap/nmap-7.99-setup.exe")
            return False

        return False
