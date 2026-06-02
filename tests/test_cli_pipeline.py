from pathlib import Path

from assetmap import cli
from assetmap.config import AppConfig


def test_manual_import_next_command_quotes_paths_with_spaces():
    command = cli.manual_import_next_command(49, Path("data/manual assets.yaml"))

    assert command == 'assetmap run 49 --manual-file "data\\manual assets.yaml"'


def test_run_pipeline_force_changed_runs_completed_downstream(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(cli, "_stage_status_map", lambda session, task_id: {stage: "completed" for stage in cli.PIPELINE_STAGES})
    monkeypatch.setattr(cli, "_warn_environment", lambda *args, **kwargs: None)

    class FakeSubdomainService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            calls.append("subdomains")

    class FakeNmapScanService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            calls.append("port-scan")

    class FakeAssetClassifierService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            calls.append("classify")

    class FakeUrlDiscoveryService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            calls.append("url-discover")

    class FakeReportResult:
        report_path = "report.docx"
        asset_workbook_path = "assets.xlsx"
        web_workbook_path = "web.xlsx"

    class FakeReportService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            calls.append("report")
            return FakeReportResult()

    class FakeStatus:
        lines = ["ok"]

    class FakePipelineStatusService:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, task_id):
            return FakeStatus()

    monkeypatch.setattr(cli, "SubdomainService", FakeSubdomainService)
    monkeypatch.setattr(cli, "NmapScanService", FakeNmapScanService)
    monkeypatch.setattr(cli, "AssetClassifierService", FakeAssetClassifierService)
    monkeypatch.setattr(cli, "UrlDiscoveryService", FakeUrlDiscoveryService)
    monkeypatch.setattr(cli, "ReportService", FakeReportService)
    monkeypatch.setattr(cli, "PipelineStatusService", FakePipelineStatusService)

    cli._run_pipeline(object(), AppConfig(), 49, progress=lambda message: None, force_changed=True)

    assert calls == ["subdomains", "port-scan", "classify", "url-discover", "report"]


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

    monkeypatch.setattr(cli, "ReviewWorkOrderService", FakeReviewWorkOrderService)
    monkeypatch.setattr(cli, "_run_pipeline", lambda *args, **kwargs: calls.append("pipeline"))

    cli._execute_improve_actions(
        object(),
        AppConfig(),
        49,
        [{"id": "A02", "phase": "子域名/DNS", "mode": "manual", "command": "assetmap review-workorder 49"}],
        reports_dir=Path("reports"),
        progress=lambda message: None,
    )

    assert calls == ["review:49:data\\review_workorder.task_49.yaml:True"]


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

    monkeypatch.setattr(cli, "ReviewWorkOrderService", FakeReviewWorkOrderService)

    cli._execute_improve_actions(
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


def test_improve_execute_port_action_uses_sources_from_plan(monkeypatch):
    seen_sources: list[list[str]] = []
    config = AppConfig()
    config.port_scan.sources_enabled = ["fofa"]

    def fake_run_pipeline(session, cfg, task_id, **kwargs):
        seen_sources.append(list(cfg.port_scan.sources_enabled))

    monkeypatch.setattr(cli, "_run_pipeline", fake_run_pipeline)

    cli._execute_improve_actions(
        object(),
        config,
        49,
        [{"id": "A03", "phase": "端口发现", "mode": "automatic", "command": "assetmap nmap-scan 49 --sources nmap,fofa --rerun"}],
        reports_dir=Path("reports"),
        progress=lambda message: None,
    )

    assert seen_sources == [["nmap", "fofa"]]
    assert config.port_scan.sources_enabled == ["fofa"]


def test_one_click_scan_runs_discover_pipeline_and_package(monkeypatch):
    calls: list[str] = []

    class FakeDiscoveryResult:
        task_id = 49
        company_count = 3
        asset_count = 5

    class FakeDiscoveryService:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target, resume_task_id=None, fresh=False):
            calls.append(f"discover:{target}:{resume_task_id}:{fresh}")
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

    monkeypatch.setattr(cli, "DiscoveryService", FakeDiscoveryService)
    monkeypatch.setattr(cli, "_run_pipeline", lambda *args, **kwargs: calls.append(f"pipeline:{args[2]}:{kwargs.get('manual_file')}"))
    monkeypatch.setattr(cli, "DeliveryQualityService", FakeQualityService)
    monkeypatch.setattr(cli, "DeliveryPackageService", FakePackageService)
    monkeypatch.setattr(cli, "DeliveryPackageVerifier", FakeVerifier)

    task_id = cli._run_one_click_scan(
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
        "pipeline:49:data\\manual_assets.yaml",
        "quality:49:reports",
        "package:49:reports:deliveries:False",
        "verify:deliveries\\task_49.zip",
    ]
