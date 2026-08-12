from pathlib import Path

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import Company, CompanyAssetLink, CompanyEdge, InternetAsset, ScanTask
from assetmap.services.acquisition.discovery import DiscoveryService, _asset_payload


def test_persist_tyc_payload(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DiscoveryService(session, config)
    payload = {
        "companies": [
            {
                "pid": "root",
                "name": "Root Co",
                "basic": {"credit_code": "91320000ROOTROOT01", "reg_status": "存续"},
                "digital_assets": [
                    {
                        "asset_type": "domain",
                        "identifier": "root.example.cn",
                        "name": "Root portal",
                        "filing_number": "苏ICP备1号",
                    },
                    {"asset_type": "wechat_service", "identifier": "rootwx", "name": "Root服务号"},
                ],
            },
            {
                "pid": "child",
                "name": "Child Co",
                "basic": {"credit_code": "91320000CHILD00001"},
                "digital_assets": [{"asset_type": "mini_program", "identifier": "child-mini", "name": "Child小程序"}],
            },
        ],
        "edges": [
            {
                "from_pid": "root",
                "from_name": "Root Co",
                "to_pid": "child",
                "to_name": "Child Co",
                "percent_value": 60.0,
                "depth": 1,
            }
        ],
    }

    service._save_result(1, payload)

    companies = session.exec(select(Company)).all()
    edges = session.exec(select(CompanyEdge)).all()
    links = session.exec(select(CompanyAssetLink)).all()
    assets = session.exec(select(InternetAsset)).all()
    assert {company.name for company in companies} == {"Root Co", "Child Co"}
    assert len(edges) == 1
    assert len(links) == 3
    assert {asset.asset_type for asset in assets} == {
        "icp_domain",
        "wechat_service_account",
        "mini_program",
    }
    edge = edges[0]
    assert edge.cumulative_holding_ratio == 0.6
    assert edge.path == "Root Co > Child Co"


def test_resume_existing_discovery_task(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="interrupted")
    session.add(task)
    session.commit()
    session.refresh(task)
    service = DiscoveryService(session, config)
    service._run_collector = lambda task_id, target, fresh=False: {  # type: ignore[method-assign]
        "companies": [{"pid": "root", "name": target, "digital_assets": []}],
        "edges": [],
    }

    result = service.run(None, resume_task_id=task.id)

    resumed = session.get(ScanTask, task.id)
    assert result.task_id == task.id
    assert resumed.status == "completed"


def test_discover_target_auto_resumes_latest_task(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    old = ScanTask(target="Root Co", status="interrupted")
    other = ScanTask(target="Other Co", status="interrupted")
    session.add(old)
    session.add(other)
    session.commit()
    session.refresh(old)
    session.refresh(other)
    service = DiscoveryService(session, config)
    calls = []
    service._run_collector = lambda task_id, target, fresh=False: calls.append((task_id, target, fresh)) or {  # type: ignore[method-assign]
        "companies": [{"pid": "root", "name": target, "digital_assets": []}],
        "edges": [],
    }

    result = service.run("Root Co")

    assert result.task_id == old.id
    assert calls == [(old.id, "Root Co", False)]


def test_discover_refresh_starts_new_task(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    old = ScanTask(target="Root Co", status="completed")
    session.add(old)
    session.commit()
    session.refresh(old)
    service = DiscoveryService(session, config)
    calls = []
    service._run_collector = lambda task_id, target, fresh=False: calls.append((task_id, target, fresh)) or {  # type: ignore[method-assign]
        "companies": [{"pid": "root", "name": target, "digital_assets": []}],
        "edges": [],
    }

    result = service.run("Root Co", fresh=True)

    assert result.task_id != old.id
    assert calls == [(result.task_id, "Root Co", True)]


def test_asset_identifier_normalization():
    assert _asset_payload({"asset_type": "domain", "identifier": "HTTPS://WWW.Example.CN/login"}) == (
        "icp_domain",
        "www.example.cn",
        "HTTPS://WWW.Example.CN/login",
    )
    assert _asset_payload({"asset_type": "domain", "identifier": "", "url": "['https://portal.example.cn']"}) == (
        "icp_domain",
        "portal.example.cn",
        "portal.example.cn",
    )
    assert _asset_payload({"asset_type": "wechat", "identifier": " gh_123 ", "name": "示例公众号"}) == (
        "wechat_official_account",
        "gh_123",
        "示例公众号",
    )
    assert _asset_payload(
        {
            "asset_type": "mini_program",
            "identifier": "2943826876",
            "name": "吴都能源桩运维",
            "filing_number": "苏ICP备18011551号-4X",
        }
    ) == (
        "mini_program",
        "苏ICP备18011551号-4X",
        "吴都能源桩运维",
    )


def test_save_result_rebuilds_enscan_links_but_keeps_manual_assets(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    company = Company(name="Root Co", normalized_name="rootco")
    old_asset = InternetAsset(
        asset_type="mini_program",
        normalized_identifier="2943826876",
        display_name="旧小程序",
        raw_payload={},
    )
    manual_asset = InternetAsset(
        asset_type="ip",
        normalized_identifier="8.8.8.8",
        display_name="8.8.8.8",
        raw_payload={},
    )
    session.add(company)
    session.add(old_asset)
    session.add(manual_asset)
    session.commit()
    session.refresh(company)
    session.refresh(old_asset)
    session.refresh(manual_asset)
    session.add(
        CompanyAssetLink(
            task_id=1,
            company_id=company.id,
            asset_id=old_asset.id,
            source_tool="enscan_python",
            raw_payload={},
        )
    )
    session.add(
        CompanyAssetLink(
            task_id=1,
            company_id=company.id,
            asset_id=manual_asset.id,
            source_tool="manual_import",
            raw_payload={},
        )
    )
    session.add(
        CompanyEdge(
            task_id=1,
            parent_company_id=company.id,
            child_company_id=company.id,
            direct_holding_ratio=1,
            cumulative_holding_ratio=1,
            depth=1,
            path="stale",
        )
    )
    session.commit()
    service = DiscoveryService(session, config)

    service._save_result(
        1,
        {
            "companies": [
                {
                    "pid": "root",
                    "name": "Root Co",
                    "digital_assets": [
                        {
                            "asset_type": "mini_program",
                            "identifier": "2943826876",
                            "name": "吴都能源桩运维",
                            "filing_number": "苏ICP备18011551号-4X",
                        }
                    ],
                }
            ],
            "edges": [],
        },
    )

    links = session.exec(select(CompanyAssetLink)).all()
    assets = {asset.id: asset for asset in session.exec(select(InternetAsset)).all()}
    assert {(link.source_tool, assets[link.asset_id].normalized_identifier) for link in links} == {
        ("manual_import", "8.8.8.8"),
        ("enscan_python", "苏ICP备18011551号-4X"),
    }
    assert session.exec(select(CompanyEdge)).all() == []


def test_refresh_edge_paths_uses_cumulative_ratio(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = DiscoveryService(session, config)
    payload = {
        "companies": [
            {"pid": "root", "name": "Root Co", "digital_assets": []},
            {"pid": "child", "name": "Child Co", "digital_assets": []},
            {"pid": "grand", "name": "Grand Co", "digital_assets": []},
        ],
        "edges": [
            {"from_pid": "root", "to_pid": "child", "percent_value": 60.0, "depth": 1},
            {"from_pid": "child", "to_pid": "grand", "percent_value": 60.0, "depth": 2},
        ],
    }

    service._save_result(1, payload)

    edges = {
        (edge.parent_company_id, edge.child_company_id): edge
        for edge in session.exec(select(CompanyEdge)).all()
    }
    companies = {company.name: company for company in session.exec(select(Company)).all()}
    grand_edge = edges[(companies["Child Co"].id, companies["Grand Co"].id)]
    assert round(grand_edge.cumulative_holding_ratio, 4) == 0.36
    assert grand_edge.path == "Root Co > Child Co > Grand Co"
