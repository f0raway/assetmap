from pathlib import Path

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.services.runtime.environment import EnvironmentCheckService, _configured_secret


def test_configured_secret_rejects_placeholders():
    assert not _configured_secret("")
    assert not _configured_secret("YOUR_TOKEN")
    assert not _configured_secret("CHANGE_ME")
    assert _configured_secret("real-token")


def test_environment_check_reports_configured_and_missing_states(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("assetmap.services.runtime.environment._module_available", lambda module: False if module == "playwright.sync_api" else True)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.domain_mapping.dnsx_wordlist = str(tmp_path / "Subdomain.txt")
    config.ai.enabled = False

    results = {row["name"]: row for row in EnvironmentCheckService(config).check()}

    assert results["domain_mapping.dnsx_wordlist"]["ok"] is False
    assert results["enterprise_discovery.tycid"]["ok"] is False
    assert results["enterprise_discovery.auth_token"]["ok"] is False
    assert results["ai"]["ok"] is True
    assert results["ai"]["detail"] == "disabled"
    assert results["fofa.credentials"]["ok"] is False
    assert results["fofa.credentials"]["detail"] == "missing or placeholder"
    browser = next(row for row in results.values() if row["name"].startswith("browser:"))
    assert browser["ok"] is False
    assert browser["detail"] == "playwright not installed"


def test_environment_check_requires_fofa_credentials(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))

    results = {row["name"]: row for row in EnvironmentCheckService(config).check()}

    assert results["fofa.credentials"]["ok"] is False
    assert "missing" in results["fofa.credentials"]["detail"]
