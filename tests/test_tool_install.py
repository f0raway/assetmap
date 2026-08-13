from pathlib import Path

from assetmap.services.runtime.tool_install import TOOL_DOWNLOADS, ToolInstallService


def test_install_tools_empty_list_defaults_to_all(monkeypatch):
    called: list[str] = []

    monkeypatch.setattr(
        ToolInstallService,
        "detect_platform",
        lambda self: {"system": "darwin", "machine": "arm64", "arch": "darwin_arm64", "is_windows": False},
    )
    monkeypatch.setattr(ToolInstallService, "_install_tool", lambda self, name, platform_info: called.append(name) or True)
    monkeypatch.setattr(ToolInstallService, "_install_nmap", lambda self, platform_info: called.append("nmap") or True)

    assert ToolInstallService().run([]) is True
    assert called == ["subfinder", "dnsx", "nmap", "httpx"]


def test_download_urls_match_release_asset_names():
    service = ToolInstallService()

    assert service._download_url(TOOL_DOWNLOADS["subfinder"], "macOS_arm64") == (
        "https://github.com/projectdiscovery/subfinder/releases/download/"
        "v2.6.8/subfinder_2.6.8_macOS_arm64.zip"
    )
    assert service._download_url(TOOL_DOWNLOADS["dnsx"], "macOS_arm64") == (
        "https://github.com/projectdiscovery/dnsx/releases/download/"
        "v1.2.2/dnsx_1.2.2_macOS_arm64.zip"
    )
    assert service._download_url(TOOL_DOWNLOADS["httpx"], "macOS_arm64") == (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.10.0/httpx_1.10.0_macOS_arm64.zip"
    )


def test_normalize_executable_copies_binary(tmp_path: Path):
    source = tmp_path / "subfinder"
    source.write_text("binary", encoding="utf-8")

    ToolInstallService()._normalize_executable(tmp_path, "subfinder", is_windows=False)

    expected = tmp_path / "subfinder"
    assert expected.read_text(encoding="utf-8") == "binary"
    assert expected.stat().st_mode & 0o111
