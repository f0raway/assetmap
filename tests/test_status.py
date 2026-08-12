from pathlib import Path
from datetime import datetime, timedelta, timezone

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import (
    Company,
    CompanyAssetLink,
    CompanyEdge,
    AssetClassificationTask,
    InternetAsset,
    NmapPort,
    NmapScanTask,
    ScanTask,
    SubdomainEnumerationTask,
    SubdomainToolRun,
    UrlDiscoveryTask,
    WebEntrypoint,
)
from assetmap.cli import _coalesce_improve_actions, _quality_suggested_actions, _select_improve_actions, _should_run_stage
from assetmap.services.delivery.quality import DeliveryQualityService
from assetmap.services.operations.status import PipelineStatusService


def test_pipeline_status_suggests_next_step(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(id=1, target="示例集团有限公司", status="completed")
    company = Company(id=1, name="示例集团有限公司", normalized_name="示例集团有限公司")
    domain = InternetAsset(
        id=1,
        asset_type="icp_domain",
        normalized_identifier="example.cn",
        display_name="example.cn",
        raw_payload={},
    )
    session.add(task)
    session.add(company)
    session.add(domain)
    session.add(CompanyAssetLink(task_id=1, company_id=1, asset_id=1, source_tool="manual", raw_payload={}))
    session.commit()

    status = PipelineStatusService(session).get(1)

    assert any("discover: completed" in line for line in status.lines)
    assert status.next_step == "assetmap run <task_id> --from-stage subdomains"


def test_pipeline_status_retries_completed_subdomain_stage_with_failed_children(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ScanTask(id=1, target="示例集团有限公司", status="completed"))
    company = Company(id=1, name="示例集团有限公司", normalized_name="示例集团有限公司")
    domain = InternetAsset(
        id=1,
        asset_type="icp_domain",
        normalized_identifier="example.cn",
        display_name="example.cn",
        raw_payload={},
    )
    session.add(company)
    session.add(domain)
    session.add(CompanyAssetLink(task_id=1, company_id=1, asset_id=1, source_tool="manual", raw_payload={}))
    session.add(SubdomainEnumerationTask(scan_task_id=1, status="completed"))
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="subfinder",
            command="subfinder",
            output_path="subfinder.txt",
            status="failed",
            error_message="temporary network error",
        )
    )
    session.commit()

    status = PipelineStatusService(session).get(1)

    assert any("subdomains: completed_with_errors" in line for line in status.lines)
    assert status.next_step == "assetmap run <task_id> --from-stage subdomains"


def test_quality_treats_partial_mapping_failures_as_warnings(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DeliveryQualityService(session, config)

    incomplete, warnings = service._pipeline_issues(
        [
            ("subdomains", "completed_with_errors", "failed_items=1"),
            ("port-scan", "completed_with_errors", "failed_runs=1"),
            ("report", "completed", "artifacts=ok"),
        ]
    )

    assert incomplete == []
    assert len(warnings) == 2
    incomplete, warnings = service._pipeline_issues([("report", "completed_with_errors", "artifacts=missing")])
    assert incomplete == ["report"]
    assert warnings == []


def test_pipeline_status_marks_interrupted_stage_with_data(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ScanTask(id=1, target="示例集团有限公司", status="completed"))
    company = Company(id=1, name="示例集团有限公司", normalized_name="示例集团有限公司")
    domain = InternetAsset(
        id=1,
        asset_type="icp_domain",
        normalized_identifier="example.cn",
        display_name="example.cn",
        raw_payload={},
    )
    session.add(company)
    session.add(domain)
    session.add(CompanyAssetLink(task_id=1, company_id=1, asset_id=1, source_tool="manual", raw_payload={}))
    session.add(SubdomainEnumerationTask(scan_task_id=1, status="completed"))
    session.add(NmapScanTask(scan_task_id=1, status="interrupted"))
    session.add(NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=443, state="open"))
    session.commit()

    status = PipelineStatusService(session).get(1)

    assert any("port-scan: interrupted_with_data" in line for line in status.lines)
    assert status.next_step == "assetmap run <task_id> --from-stage port-scan --rerun-ports"


def test_pipeline_status_marks_stale_running_stage_with_data(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ScanTask(id=1, target="示例集团有限公司", status="completed"))
    session.add(Company(id=1, name="示例集团有限公司", normalized_name="示例集团有限公司"))
    session.add(
        InternetAsset(
            id=1,
            asset_type="icp_domain",
            normalized_identifier="example.cn",
            display_name="example.cn",
            raw_payload={},
        )
    )
    session.add(CompanyAssetLink(task_id=1, company_id=1, asset_id=1, source_tool="manual", raw_payload={}))
    session.add(SubdomainEnumerationTask(scan_task_id=1, status="completed"))
    session.add(NmapScanTask(scan_task_id=1, status="completed"))
    session.add(AssetClassificationTask(scan_task_id=1, status="completed"))
    session.add(
        UrlDiscoveryTask(
            scan_task_id=1,
            status="running",
            started_at=datetime.now(timezone.utc) - timedelta(hours=3),
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="portal.example.cn",
            url="https://portal.example.cn/",
            normalized_url="https://portal.example.cn/",
            evidence={"visual_analysis": {"analysis_method": "http_probe_fallback"}},
        )
    )
    session.commit()

    status = PipelineStatusService(session).get(1)

    assert any("url-discover: running_stale_with_data" in line for line in status.lines)
    assert status.next_step == "assetmap run <task_id> --from-stage url-discover --retry-failed"


def test_run_stage_decision_treats_completed_and_skipped_as_done():
    assert not _should_run_stage({"subdomains": "completed"}, "subdomains")
    assert not _should_run_stage({"subdomains": "skipped"}, "subdomains")
    assert _should_run_stage({"subdomains": "completed"}, "subdomains", force=True)
    assert _should_run_stage({"subdomains": "interrupted_with_data"}, "subdomains")


def test_improve_action_selection_and_coalesce():
    actions = [
        {"id": "A01", "phase": "企业/备案资产", "mode": "manual"},
        {"id": "A02", "phase": "子域名/DNS", "mode": "automatic"},
        {"id": "A03", "phase": "服务识别/URL", "mode": "automatic"},
        {"id": "A04", "phase": "URL视觉识别", "mode": "automatic"},
        {"id": "A05", "phase": "报告交付", "mode": "automatic"},
    ]

    automatic = _select_improve_actions(actions, "automatic", include_deliver=False)
    assert [item["id"] for item in automatic] == ["A02", "A03", "A04"]
    all_actions = _select_improve_actions(actions, "all", include_deliver=True)
    assert [item["id"] for item in all_actions] == ["A01", "A02", "A03", "A04", "A05"]
    assert [item["id"] for item in _coalesce_improve_actions(all_actions)] == ["A01", "A02", "A05"]


def test_quality_suggested_actions_parses_quality_output():
    actions = _quality_suggested_actions(
        [
            "Quality: WARN",
            "",
            "Suggested next actions:",
            "- 生成缺口补充模板：assetmap asset-gap-template 1 --priority high-medium --include-partial --force --output data/manual_assets.task_1.gaps.yaml",
            "- 补充模板后执行：assetmap run 1 --manual-file data/manual_assets.task_1.gaps.yaml",
        ]
    )

    assert actions == [
        "生成缺口补充模板：assetmap asset-gap-template 1 --priority high-medium --include-partial --force --output data/manual_assets.task_1.gaps.yaml",
        "补充模板后执行：assetmap run 1 --manual-file data/manual_assets.task_1.gaps.yaml",
    ]


def test_quality_check_fails_when_pipeline_and_artifacts_are_missing(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ScanTask(id=1, target="示例集团有限公司", status="pending"))
    session.commit()

    result = DeliveryQualityService(session, config).check(1, output_dir=tmp_path / "reports")

    assert result.status == "FAIL"
    assert any("流程未完成" in item for item in result.failures)
    assert any("Word报告不存在" in item for item in result.failures)
    assert any("assetmap run 1" in line for line in result.lines)


def test_quality_check_suggests_high_medium_gap_template(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    parent = Company(id=1, name="示例集团有限公司", normalized_name="示例集团有限公司")
    child = Company(id=2, name="示例子公司", normalized_name="示例子公司")
    domain = InternetAsset(
        id=1,
        asset_type="icp_domain",
        normalized_identifier="example.cn",
        display_name="example.cn",
        raw_payload={},
    )
    session.add(ScanTask(id=1, target="示例集团有限公司", status="completed"))
    session.add(parent)
    session.add(child)
    session.add(domain)
    session.add(
        CompanyEdge(
            task_id=1,
            parent_company_id=1,
            child_company_id=2,
            direct_holding_ratio=1,
            cumulative_holding_ratio=1,
            depth=1,
            path="示例集团有限公司 > 示例子公司",
        )
    )
    session.add(CompanyAssetLink(task_id=1, company_id=1, asset_id=1, source_tool="manual", raw_payload={}))
    session.commit()

    result = DeliveryQualityService(session, config).check(1, output_dir=tmp_path / "reports")

    assert any("asset-gap-template 1 --priority high-medium" in line for line in result.lines)


def test_quality_next_actions_only_retry_failed_visual_items(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DeliveryQualityService(session, config)
    task = ScanTask(id=1, target="示例集团有限公司", status="completed")
    coverage_rows = [{"环节": "URL视觉识别", "缺口等级": "低"}]

    manual_only = service._next_actions(
        task,
        coverage_rows,
        [{"复核类型": "manual_http_fallback_review", "识别方式": "http_probe_fallback", "分析错误": ""}],
        [],
        ["存在低等级覆盖缺口: URL视觉识别"],
    )
    retry_needed = service._next_actions(
        task,
        coverage_rows,
        [{"复核类型": "automatic_retry", "识别方式": "", "分析错误": ""}],
        [],
        ["存在低等级覆盖缺口: URL视觉识别"],
    )

    assert any("当前无自动重试项" in action for action in manual_only)
    assert any("assetmap import-review 1 --file data/review_workorder.task_1.yaml" in action for action in manual_only)
    assert not any("url-discover" in action for action in manual_only)
    assert any("url-discover 1 --retry-failed" in action for action in retry_needed)


def test_quality_next_actions_split_dns_manual_review_from_rerun(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DeliveryQualityService(session, config)
    task = ScanTask(id=1, target="示例集团有限公司", status="completed")

    manual_dns = service._next_actions(
        task,
        [{"环节": "子域名/DNS", "指标": "DNS 解析复核质量", "缺口等级": "中"}],
        [],
        [],
        ["存在中等级覆盖缺口: 子域名/DNS"],
    )
    rerun_dns = service._next_actions(
        task,
        [{"环节": "子域名/DNS", "指标": "子域名枚举质量", "缺口等级": "低"}],
        [],
        [],
        ["存在低等级覆盖缺口: 子域名/DNS"],
    )

    assert any("DNS复核清单" in action for action in manual_dns)
    assert not any("--rerun-subdomain-tools" in action for action in manual_dns)
    assert any("--rerun-subdomain-tools" in action for action in rerun_dns)


def test_quality_next_actions_explain_passive_only_port_evidence(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DeliveryQualityService(session, config)
    task = ScanTask(id=1, target="示例集团有限公司", status="completed")

    actions = service._next_actions(
        task,
        [{"环节": "端口发现", "指标": "端口证据来源质量", "缺口等级": "低"}],
        [],
        [],
        ["存在低等级覆盖缺口: 端口发现"],
    )

    assert any("仅被动FOFA证据" in action for action in actions)
    assert any("assetmap nmap-scan 1 --sources nmap,fofa --rerun" in action for action in actions)


def test_quality_next_actions_split_service_manual_review_from_rerun(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DeliveryQualityService(session, config)
    task = ScanTask(id=1, target="示例集团有限公司", status="completed")

    manual_service = service._next_actions(
        task,
        [{"环节": "服务识别/URL", "指标": "服务分类复核", "缺口等级": "低"}],
        [],
        [],
        ["存在低等级覆盖缺口: 服务识别/URL"],
    )
    rerun_service = service._next_actions(
        task,
        [{"环节": "服务识别/URL", "指标": "Web 服务入口覆盖", "缺口等级": "高"}],
        [],
        [],
        ["存在高等级覆盖缺口: 服务识别/URL"],
    )

    assert any("服务识别台账" in action for action in manual_service)
    assert not any("--rerun-classify" in action for action in manual_service)
    assert any("--rerun-classify" in action for action in rerun_service)
