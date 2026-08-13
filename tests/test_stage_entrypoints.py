from pathlib import Path

import pytest

from assetmap.config import AppConfig, DatabaseConfig, write_sample_config
from assetmap.services.acquisition.discovery import DiscoveryResult
from assetmap.stages import enterprise_discovery
from assetmap.stages import domain_mapping
from assetmap.stages import port_discovery
from assetmap.stages import report_generation
from assetmap.stages import service_identification
from assetmap.stages import web_identification


def test_enterprise_stage_run_reuses_production_service(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    calls = {}

    class FakeDiscoveryService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config
            calls["progress"] = progress

        def run(self, target, resume_task_id, fresh):
            calls.update(target=target, task_id=resume_task_id, fresh=fresh)
            return DiscoveryResult(task_id=7, company_count=2, asset_count=3)

    monkeypatch.setattr(enterprise_discovery, "DiscoveryService", FakeDiscoveryService)
    logs = []

    result = enterprise_discovery.run(config, target="测试企业", fresh=True, progress=logs.append)

    assert result.task_id == 7
    assert calls["config"] is config
    assert calls["target"] == "测试企业"
    assert calls["task_id"] is None
    assert calls["fresh"] is True


def test_enterprise_stage_rejects_ambiguous_debug_inputs(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))

    with pytest.raises(ValueError, match="不能同时使用"):
        enterprise_discovery.run(config, target="测试企业", task_id=1)


def test_enterprise_stage_main_loads_config_and_reports_result(tmp_path: Path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    monkeypatch.setattr(
        enterprise_discovery,
        "run",
        lambda *args, **kwargs: DiscoveryResult(task_id=9, company_count=4, asset_count=5),
    )

    code = enterprise_discovery.main(["--target", "测试企业", "--config", str(config_path)])

    assert code == 0
    assert "task_id=9" in capsys.readouterr().out


def test_domain_mapping_stage_uses_resolved_database_url(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url="sqlite:///data/assetmap.db")).bind_config_path(tmp_path / "config.yaml")
    calls = {}

    class FakeService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config

        def run(self, task_id, run_ai, rerun_tools, rerun_dns):
            calls.update(task_id=task_id, run_ai=run_ai, rerun_tools=rerun_tools, rerun_dns=rerun_dns)
            return 3

    monkeypatch.setattr(domain_mapping, "SubdomainService", FakeService)

    assert domain_mapping.run(config, task_id=3, rerun_tools=True) == 3
    assert calls == {"config": config, "task_id": 3, "run_ai": True, "rerun_tools": True, "rerun_dns": False}


def test_port_discovery_stage_reuses_production_service(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    calls = {}

    class FakeService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config

        def run(self, task_id, rerun):
            calls.update(task_id=task_id, rerun=rerun)
            return 4

    monkeypatch.setattr(port_discovery, "NmapScanService", FakeService)

    assert port_discovery.run(config, task_id=3, rerun=True) == 4
    assert calls == {"config": config, "task_id": 3, "rerun": True}


def test_service_identification_stage_reuses_production_service(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    calls = {}

    class FakeService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config

        def run(self, task_id, rerun):
            calls.update(task_id=task_id, rerun=rerun)
            return 5

    monkeypatch.setattr(service_identification, "AssetClassifierService", FakeService)

    assert service_identification.run(config, task_id=3, rerun=True) == 5
    assert calls == {"config": config, "task_id": 3, "rerun": True}


def test_web_identification_stage_reuses_production_service(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    calls = {}

    class FakeService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config

        def run(self, task_id, rerun, retry_failed):
            calls.update(task_id=task_id, rerun=rerun, retry_failed=retry_failed)
            return 6

    monkeypatch.setattr(web_identification, "UrlDiscoveryService", FakeService)

    assert web_identification.run(config, task_id=3, retry_failed=True) == 6
    assert calls == {"config": config, "task_id": 3, "rerun": False, "retry_failed": True}


def test_report_generation_stage_reuses_production_service(tmp_path: Path, monkeypatch):
    from assetmap.services.delivery.report import ReportResult

    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    calls = {}
    expected = ReportResult(tmp_path / "report.docx", tmp_path / "assets.xlsx", tmp_path / "web.xlsx", 4)

    class FakeService:
        def __init__(self, session, received_config, progress):
            calls["config"] = received_config

        def run(self, task_id, output_dir, rerun_ai):
            calls.update(task_id=task_id, output_dir=output_dir, rerun_ai=rerun_ai)
            return expected

    monkeypatch.setattr(report_generation, "ReportService", FakeService)

    assert report_generation.run(config, task_id=3, output_dir=tmp_path / "reports", rerun_ai=True) == expected
    assert calls == {"config": config, "task_id": 3, "output_dir": tmp_path / "reports", "rerun_ai": True}
