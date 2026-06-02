from pathlib import Path

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.services.environment import EnvironmentCheckService, _configured_secret


def test_configured_secret_rejects_placeholders():
    assert not _configured_secret("")
    assert not _configured_secret("YOUR_TOKEN")
    assert not _configured_secret("CHANGE_ME")
    assert _configured_secret("real-token")


def test_environment_check_reports_configured_and_disabled_states(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.enscan.script = str(tmp_path / "tyc.py")
    config.tools.wordlist = str(tmp_path / "Subdomain.txt")
    config.tools.subdomain_tools_enabled = []
    config.port_scan.sources_enabled = []
    config.url_discovery.browser_channel = "chromium"

    results = {row["name"]: row for row in EnvironmentCheckService(config).check()}

    assert results["enscan.script"]["ok"] is False
    assert results["tools.wordlist"]["ok"] is False
    assert results["enscan.tycid"]["ok"] is False
    assert results["enscan.auth_token"]["ok"] is False
    assert results["ai"]["ok"] is True
    assert results["ai"]["detail"] == "disabled"
    assert results["fofa"]["ok"] is True
    assert results["fofa"]["detail"] == "disabled"
    assert results["browser"]["ok"] is True


def test_environment_check_requires_fofa_when_enabled(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.tools.subdomain_tools_enabled = []
    config.port_scan.sources_enabled = ["fofa"]
    config.url_discovery.browser_channel = "chromium"

    results = {row["name"]: row for row in EnvironmentCheckService(config).check()}

    assert results["fofa.credentials"]["ok"] is False
    assert "enabled" in results["fofa.credentials"]["detail"]
