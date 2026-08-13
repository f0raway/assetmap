from pathlib import Path

import pytest
import typer

from assetmap import cli
from assetmap.cli import pipeline as pipeline_cli
from assetmap.cli import review as review_cli
from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import WebEntrypoint
from assetmap.stages import pipeline as stage_pipeline


def test_manual_import_next_command_quotes_paths_with_spaces():
    command = cli.manual_import_next_command(49, Path("data/manual assets.yaml"))

    assert command == 'assetmap run 49 --manual-file "data/manual assets.yaml"'


def test_visual_gaps_do_not_retry_completed_http_probe_fallbacks(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebEntrypoint(
            scan_task_id=49,
            host="fallback.example.cn",
            url="https://fallback.example.cn/",
            normalized_url="https://fallback.example.cn/",
            evidence={"visual_analysis": {"analysis_method": "http_probe_fallback"}},
        )
    )
    session.commit()

    assert not stage_pipeline._has_incomplete_page_identification(config, 49)


def test_run_pipeline_force_changed_runs_completed_downstream(monkeypatch):
    seen: dict = {}

    def fake_run(config, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(pipeline_cli.stage_pipeline, "run", fake_run)
    pipeline_cli._run_pipeline(object(), AppConfig(), 49, progress=lambda message: None, force_changed=True)

    assert seen["task_id"] == 49
    assert seen["force_changed"] is True
    assert seen["from_stage"] == "subdomains"
    assert seen["to_stage"] == "report"


def test_improve_execute_manual_review_action_writes_workorder(monkeypatch):
    calls: list[str] = []

    class FakeReviewResult:
        path = "data/review_workorder.task_49.yaml"
        total_items = 3

    class FakeReviewWorkOrderService:
        def __init__(self, *args, **kwargs):
            pass

        def write(self, task_id, path, force=False):
            calls.append(f"review:{task_id}:{path}:{force}")
            return FakeReviewResult()

    monkeypatch.setattr(review_cli, "ReviewWorkOrderService", FakeReviewWorkOrderService)
    monkeypatch.setattr(pipeline_cli, "_run_pipeline", lambda *args, **kwargs: calls.append("pipeline"))

    review_cli._execute_improve_actions(
        object(),
        AppConfig(),
        49,
        [{"id": "A02", "phase": "子域名/DNS", "mode": "manual", "command": "assetmap review-workorder 49"}],
        reports_dir=Path("reports"),
        progress=lambda message: None,
    )

    assert calls == ["review:49:data/review_workorder.task_49.yaml:True"]


def test_improve_execute_deduplicates_manual_review_workorder(monkeypatch):
    calls: list[str] = []

    class FakeReviewResult:
        path = "data/review_workorder.task_49.yaml"
        total_items = 3

    class FakeReviewWorkOrderService:
        def __init__(self, *args, **kwargs):
            pass

        def write(self, task_id, path, force=False):
            calls.append(f"review:{task_id}")
            return FakeReviewResult()

    monkeypatch.setattr(review_cli, "ReviewWorkOrderService", FakeReviewWorkOrderService)

    review_cli._execute_improve_actions(
        object(),
        AppConfig(),
        49,
        [
            {"id": "A02", "phase": "子域名/DNS", "mode": "manual", "command": "assetmap review-workorder 49"},
            {"id": "A04", "phase": "服务识别/URL", "mode": "manual", "command": "assetmap review-workorder 49"},
            {"id": "A05", "phase": "URL视觉识别", "mode": "manual", "command": "assetmap review-workorder 49"},
        ],
        reports_dir=Path("reports"),
        progress=lambda message: None,
    )

    assert calls == ["review:49"]


def test_improve_execute_port_action_uses_fixed_sources(monkeypatch):
    seen_calls: list[dict] = []
    config = AppConfig()

    def fake_run_pipeline(session, cfg, task_id, **kwargs):
        seen_calls.append(kwargs)

    monkeypatch.setattr(pipeline_cli, "_run_pipeline", fake_run_pipeline)

    review_cli._execute_improve_actions(
        object(),
        config,
        49,
        [{"id": "A03", "phase": "端口发现", "mode": "automatic", "command": "assetmap nmap-scan 49 --rerun"}],
        reports_dir=Path("reports"),
        progress=lambda message: None,
    )

    assert len(seen_calls) == 1
    assert seen_calls[0]["from_stage"] == "port-scan"
    assert seen_calls[0]["rerun_ports"] is True


def test_one_click_scan_runs_discover_pipeline_and_package(monkeypatch):
    calls: list[str] = []

    class FakeDiscoveryResult:
        task_id = 49
        company_count = 3
        asset_count = 5

    def fake_enterprise_discovery(config, *, target=None, task_id=None, fresh=False, progress=None):
        calls.append(f"discover:{target}:{task_id}:{fresh}")
        return FakeDiscoveryResult()

    class FakeQuality:
        status = "PASS"
        warnings = []
        failures = []

    class FakeQualityService:
        def __init__(self, *args, **kwargs):
            pass

        def check(self, task_id, output_dir=Path("reports")):
            calls.append(f"quality:{task_id}:{output_dir}")
            return FakeQuality()

    class FakePackage:
        package_dir = Path("deliveries/task_49")
        zip_path = Path("deliveries/task_49.zip")

    class FakePackageService:
        def __init__(self, *args, **kwargs):
            pass

        def package(self, task_id, reports_dir=Path("reports"), output_dir=Path("deliveries"), strict=False):
            calls.append(f"package:{task_id}:{reports_dir}:{output_dir}:{strict}")
            return FakePackage()

    class FakeVerification:
        lines = ["Package verification: PASS"]
        failures = []

    class FakeVerifier:
        def verify(self, package_path):
            calls.append(f"verify:{package_path}")
            return FakeVerification()

    monkeypatch.setattr(pipeline_cli.stage_pipeline.enterprise_discovery, "run", fake_enterprise_discovery)
    monkeypatch.setattr(pipeline_cli, "_require_full_scan_environment", lambda *args: None)
    monkeypatch.setattr(pipeline_cli, "_run_pipeline", lambda *args, **kwargs: calls.append(f"pipeline:{args[2]}:{kwargs.get('manual_file')}"))
    monkeypatch.setattr(pipeline_cli, "DeliveryQualityService", FakeQualityService)
    monkeypatch.setattr(pipeline_cli, "DeliveryPackageService", FakePackageService)
    monkeypatch.setattr(pipeline_cli, "DeliveryPackageVerifier", FakeVerifier)

    task_id = pipeline_cli._run_one_click_scan(
        object(),
        AppConfig(),
        "Root Co",
        refresh=True,
        manual_file=Path("data/manual_assets.yaml"),
        progress=lambda message: None,
    )

    assert task_id == 49
    assert calls == [
        "discover:Root Co:None:True",
        "pipeline:49:data/manual_assets.yaml",
        "quality:49:reports",
        "package:49:reports:deliveries:False",
        "verify:deliveries/task_49.zip",
    ]


def test_one_click_scan_preflight_stops_before_external_collection(monkeypatch):
    progress: list[str] = []

    class FakeEnvironmentCheckService:
        def __init__(self, config):
            pass

        def check(self):
            return [
                {
                    "name": "fofa.credentials",
                    "ok": False,
                    "detail": "enabled but missing or placeholder",
                    "suggestion": "Set fofa.email and fofa.api_key in config.yaml.",
                }
            ]

    monkeypatch.setattr(pipeline_cli, "EnvironmentCheckService", FakeEnvironmentCheckService)

    with pytest.raises(typer.Exit) as exc_info:
        pipeline_cli._require_full_scan_environment(AppConfig(), progress.append)

    assert exc_info.value.exit_code == 2
    assert progress == [
        "[scan] preflight failed; no external collection was started.",
        "[scan] missing fofa.credentials: enabled but missing or placeholder",
        "[scan] suggestion: Set fofa.email and fofa.api_key in config.yaml.",
    ]
