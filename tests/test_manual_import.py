import json
import xml.etree.ElementTree as ET
from pathlib import Path

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import AiAnalysis, Company, CompanyAssetLink, CompanyEdge, DnsRecord, InternetAsset, NmapPort, NmapScanRun, ScanTask, SourceRawRecord, SubdomainRecord, WebEntrypoint
from assetmap.services.acquisition.manual_import import ManualAssetImportService, write_manual_asset_template
from assetmap.services.operations.maintenance import MaintenanceService
from assetmap.services.mapping.fofa import FofaClient, FofaPort
from assetmap.services.mapping.nmap_scan import NMAP_FOFA_VALIDATION_PREFIX, NmapScanService
from assetmap.services.delivery.exporter import ExportService
from assetmap.services.delivery.report import ReportService


def test_manual_import_adds_full_asset_set(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    company = Company(name="Root Co", normalized_name="rootco")
    session.add(task)
    session.add(company)
    session.commit()
    session.refresh(task)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
domains:
  - root.example.cn
subdomains:
  - oa.root.example.cn
ips:
  - 8.8.8.8
urls:
  - url: https://portal.root.example.cn/login
    system_name: Root Portal
    site_purpose: 登录门户
apps:
  - name: Root App
    package: cn.example.root
mini_programs:
  - name: Root Mini
    identifier: "123456"
    filing_number: 苏ICP备202300001号-1X
wechat_official_accounts:
  - name: Root Official
    account: root-official
wechat_service_accounts:
  - name: Root Service
    account: root-service
emails:
  - SECURITY@Root.Example.cn
""".strip(),
        encoding="utf-8",
    )

    result = ManualAssetImportService(session).run(task.id, manual_file)

    assert result.units == 1
    assert result.units_with_input == 1
    assert result.empty_units in (None, [])
    assert result.domains == 1
    assert result.subdomains == 1
    assert result.ips == 1
    assert result.urls == 1
    assert result.assets == 5
    assets = session.exec(select(InternetAsset)).all()
    assert {asset.asset_type for asset in assets} == {
        "icp_domain",
        "subdomain",
        "ip",
        "app",
        "mini_program",
        "wechat_official_account",
        "wechat_service_account",
        "email",
    }
    assert len(session.exec(select(CompanyAssetLink)).all()) == 8
    subdomain = session.exec(select(SubdomainRecord)).one()
    assert subdomain.root_domain == "root.example.cn"
    assert subdomain.fqdn == "oa.root.example.cn"
    dns_record = session.exec(select(DnsRecord)).one()
    assert dns_record.value == "8.8.8.8"
    assert dns_record.raw_payload["kind"] == "manual_ip"
    web = session.exec(select(WebEntrypoint)).one()
    assert web.normalized_url == "https://portal.root.example.cn/login"
    assert web.port == 443
    assert web.evidence["manual_import"]["unit"] == "Root Co"
    assert web.evidence["visual_analysis"]["system_name"] == "Root Portal"
    mini = session.exec(
        select(InternetAsset).where(InternetAsset.asset_type == "mini_program")
    ).one()
    assert mini.normalized_identifier == "苏ICP备202300001号-1X"
    assert NmapScanService(session, config)._targets(task.id) == ["8.8.8.8"]
    assert NmapScanService(session, config)._targets_by_source(task.id) == {
        "ai": [],
        "manual": ["8.8.8.8"],
        "dns_public": [],
    }


def test_write_manual_asset_template(tmp_path: Path):
    path = write_manual_asset_template(tmp_path / "manual_assets.example.yaml")

    content = path.read_text(encoding="utf-8")
    assert "units:" in content
    assert "unit:" in content
    assert "domains:" in content
    assert "apps:" in content
    assert "mini_programs:" in content
    assert "wechat_official_accounts:" in content
    assert "wechat_service_accounts:" in content
    assert "emails:" in content
    assert "urls:" in content
    assert "source_urls:" in content
    assert "review_checklist:" in content
    assert "review_status: no_assets_found" in content


def test_manual_import_supports_item_level_company_owner(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    root = Company(name="Root Co", normalized_name="rootco")
    child = Company(name="Child Co", normalized_name="childco")
    session.add(task)
    session.add(root)
    session.add(child)
    session.commit()
    session.refresh(task)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
company: Root Co
domains:
  - root.example.cn
subdomains:
  - fqdn: oa.root.example.cn
    company: Child Co
ips:
  - ip: 8.8.4.4
    company: Child Co
apps:
  - name: Root App
    package: cn.example.root
  - name: Child App
    package: cn.example.child
    company: Child Co
""".strip(),
        encoding="utf-8",
    )

    ManualAssetImportService(session).run(task.id, manual_file)

    links = session.exec(select(CompanyAssetLink)).all()
    assets = {asset.id: asset for asset in session.exec(select(InternetAsset)).all()}
    companies = {company.id: company for company in session.exec(select(Company)).all()}
    owner_by_identifier = {
        assets[link.asset_id].normalized_identifier: companies[link.company_id].name
        for link in links
    }
    assert owner_by_identifier["root.example.cn"] == "Root Co"
    assert owner_by_identifier["oa.root.example.cn"] == "Child Co"
    assert owner_by_identifier["8.8.4.4"] == "Child Co"
    assert owner_by_identifier["cn.example.root"] == "Root Co"
    assert owner_by_identifier["cn.example.child"] == "Child Co"


def test_manual_import_prefers_unit_group_format(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    session.add(task)
    session.commit()
    session.refresh(task)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
units:
  - unit: Root Co
    domains:
      - root.example.cn
    subdomains:
      - oa.root.example.cn
    mini_programs:
      - name: Root Mini
        appid: wx-root
  - unit: Child Co
    domains:
      - child.example.cn
    wechat_official_accounts:
      - name: Child Official
        account: child-official
""".strip(),
        encoding="utf-8",
    )

    result = ManualAssetImportService(session).run(task.id, manual_file)

    assert result.units == 2
    assert result.units_with_input == 2
    links = session.exec(select(CompanyAssetLink)).all()
    assets = {asset.id: asset for asset in session.exec(select(InternetAsset)).all()}
    companies = {company.id: company for company in session.exec(select(Company)).all()}
    owner_by_identifier = {
        assets[link.asset_id].normalized_identifier: companies[link.company_id].name
        for link in links
    }
    assert owner_by_identifier["root.example.cn"] == "Root Co"
    assert owner_by_identifier["oa.root.example.cn"] == "Root Co"
    assert owner_by_identifier["wx-root"] == "Root Co"
    assert owner_by_identifier["child.example.cn"] == "Child Co"
    assert owner_by_identifier["child-official"] == "Child Co"


def test_manual_import_merges_chinese_and_english_alias_fields(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    session.add(task)
    session.commit()
    session.refresh(task)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
units:
  - unit: Root Co
    domains:
      - root.example.cn
    备案网站:
      - beian.example.cn
    subdomains:
      - oa.root.example.cn
    子域名:
      - vpn.root.example.cn
    ips:
      - 8.8.8.8
    公网IP:
      - 1.1.1.1
    urls:
      - https://portal.root.example.cn/
    Web入口:
      - https://vpn.root.example.cn/
    APP备案:
      - name: Root App
        package: cn.example.root
    微信小程序备案:
      - name: Root Mini
        appid: wx-root
    微信公众号备案:
      - name: Root Official
        account: gh_root
    微信服务号备案:
      - name: Root Service
        account: gh_service
    邮箱地址:
      - SECURITY@Root.Example.cn
""".strip(),
        encoding="utf-8",
    )

    result = ManualAssetImportService(session).run(task.id, manual_file)

    assert result.domains == 2
    assert result.subdomains == 2
    assert result.ips == 2
    assert result.urls == 2
    assert result.assets == 5
    identifiers = {asset.normalized_identifier for asset in session.exec(select(InternetAsset)).all()}
    assert {
        "root.example.cn",
        "beian.example.cn",
        "oa.root.example.cn",
        "vpn.root.example.cn",
        "8.8.8.8",
        "1.1.1.1",
        "cn.example.root",
        "wx-root",
        "gh_root",
        "gh_service",
        "security@root.example.cn",
    } <= identifiers
    assert len(session.exec(select(WebEntrypoint)).all()) == 2


def test_manual_import_reports_empty_units(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    session.add(task)
    session.commit()
    session.refresh(task)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
units:
  - unit: Empty Co
    domains: []
    search_keywords:
      - Empty Co 官网
    review_status: pending
  - unit: Filled Co
    domains:
      - filled.example.cn
""".strip(),
        encoding="utf-8",
    )

    result = ManualAssetImportService(session).run(task.id, manual_file)

    assert result.units == 2
    assert result.units_with_input == 1
    assert result.empty_units == ["Empty Co"]
    assert result.domains == 1


def test_manual_import_records_no_asset_attestation(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(id=1, target="Root Co", status="completed")
    root = Company(id=1, name="Root Co", normalized_name="rootco")
    empty = Company(id=2, name="Empty Co", normalized_name="emptyco")
    session.add(task)
    session.add(root)
    session.add(empty)
    session.add(
        CompanyEdge(
            task_id=1,
            parent_company_id=1,
            child_company_id=2,
            direct_holding_ratio=1,
            cumulative_holding_ratio=1,
            depth=1,
            path="Root Co > Empty Co",
        )
    )
    session.commit()

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
units:
  - unit: Empty Co
    domains: []
    review_status: no_assets_found
    source_urls:
      - https://beian.miit.gov.cn/
    notes: 工信部备案、官网、公众号和应用商店均未发现独立资产。
""".strip(),
        encoding="utf-8",
    )

    result = ManualAssetImportService(session).run(task.id, manual_file)

    assert result.units == 1
    assert result.units_with_input == 1
    assert result.empty_units in (None, [])
    assert result.no_asset_reviews == 1
    record = session.exec(select(SourceRawRecord).where(SourceRawRecord.action == "no_assets_found")).one()
    assert record.response_json["unit"] == "Empty Co"
    assert record.response_json["review_status"] == "no_assets_found"
    context = ReportService(session, config)._context(ExportService(session)._bundle(task.id))
    by_unit = {row["单位"]: row for row in context["unit_coverage_rows"]}
    assert by_unit["Empty Co"]["覆盖状态"] == "人工确认无独立互联网资产"
    assert by_unit["Empty Co"]["复核优先级"] == "无"
    assert "工信部备案" in by_unit["Empty Co"]["人工复核依据"]


def test_manual_import_reports_invalid_entries(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    session.add(task)
    session.commit()
    session.refresh(task)
    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
units:
  - unit: Root Co
    domains:
      - "not a domain"
    ips:
      - 192.168.1.1
      - 8.8.8.8
""".strip(),
        encoding="utf-8",
    )
    logs = []

    result = ManualAssetImportService(session, progress=logs.append).run(task.id, manual_file)

    assert result.ips == 1
    assert result.skipped == 2
    assert any("invalid domain" in warning for warning in result.warnings or [])
    assert any("non-public IP" in warning for warning in result.warnings or [])
    assert any(line.startswith("[manual]") for line in logs)


def test_dedupe_asset_links_merges_sources(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    company = Company(name="Root Co", normalized_name="rootco")
    asset = InternetAsset(
        asset_type="icp_domain",
        normalized_identifier="root.example.cn",
        display_name="root.example.cn",
        raw_payload={},
    )
    session.add(task)
    session.add(company)
    session.add(asset)
    session.commit()
    session.refresh(task)
    session.refresh(company)
    session.refresh(asset)
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=asset.id, source_tool="enscan_python", raw_payload={}))
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=asset.id, source_tool="manual_import", raw_payload={}))
    session.commit()

    result = MaintenanceService(session).dedupe_asset_links(task.id)

    links = session.exec(select(CompanyAssetLink)).all()
    assert result.removed_links == 1
    assert len(links) == 1
    assert links[0].raw_payload["sources"] == ["enscan_python", "manual_import"]
    session.close()

    reopened = get_session(engine)
    persisted = reopened.exec(select(CompanyAssetLink)).one()
    assert persisted.raw_payload["sources"] == ["enscan_python", "manual_import"]
    assert len(persisted.raw_payload["evidence"]) == 2


def test_manual_import_merges_global_asset_raw_payload_without_overwriting(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    company = Company(name="Root Co", normalized_name="rootco")
    asset = InternetAsset(
        asset_type="wechat_official_account",
        normalized_identifier="gh_root",
        display_name="Root Official",
        raw_payload={"source": "enscan_python", "raw": {"account": "gh_root"}},
    )
    session.add(task)
    session.add(company)
    session.add(asset)
    session.commit()
    session.refresh(task)
    session.refresh(company)
    session.refresh(asset)

    manual_file = tmp_path / "manual_assets.yaml"
    manual_file.write_text(
        """
unit: Root Co
wechat_official_accounts:
  - name: Root Official
    account: gh_root
    note: 人工确认
""".strip(),
        encoding="utf-8",
    )

    ManualAssetImportService(session).run(task.id, manual_file)

    refreshed = session.get(InternetAsset, asset.id)
    assert refreshed.raw_payload["sources"] == ["enscan_python", "manual_import"]
    assert len(refreshed.raw_payload["evidence"]) == 2


def test_dedupe_asset_links_merges_same_display_name(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    company = Company(name="Root Co", normalized_name="rootco")
    auto_asset = InternetAsset(
        asset_type="mini_program",
        normalized_identifier="123456",
        display_name="Root Mini",
        raw_payload={},
    )
    manual_asset = InternetAsset(
        asset_type="mini_program",
        normalized_identifier="root mini",
        display_name="Root Mini",
        raw_payload={},
    )
    session.add(task)
    session.add(company)
    session.add(auto_asset)
    session.add(manual_asset)
    session.commit()
    session.refresh(task)
    session.refresh(company)
    session.refresh(auto_asset)
    session.refresh(manual_asset)
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=auto_asset.id, source_tool="enscan_python", raw_payload={}))
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=manual_asset.id, source_tool="manual_import", raw_payload={}))
    session.commit()

    result = MaintenanceService(session).dedupe_asset_links(task.id)

    links = session.exec(select(CompanyAssetLink)).all()
    assert result.removed_links == 1
    assert len(links) == 1


def test_dedupe_asset_links_prefers_stronger_named_identifier(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    task = ScanTask(target="Root Co", status="completed")
    company = Company(name="Root Co", normalized_name="rootco")
    manual_asset = InternetAsset(
        asset_type="mini_program",
        normalized_identifier="root mini",
        display_name="Root Mini",
        raw_payload={},
    )
    filing_asset = InternetAsset(
        asset_type="mini_program",
        normalized_identifier="苏ICP备202300001号-1X",
        display_name="Root Mini",
        raw_payload={},
    )
    session.add(task)
    session.add(company)
    session.add(manual_asset)
    session.add(filing_asset)
    session.commit()
    session.refresh(task)
    session.refresh(company)
    session.refresh(manual_asset)
    session.refresh(filing_asset)
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=manual_asset.id, source_tool="manual_import", raw_payload={}))
    session.add(CompanyAssetLink(task_id=task.id, company_id=company.id, asset_id=filing_asset.id, source_tool="enscan_python", raw_payload={}))
    session.commit()

    result = MaintenanceService(session).dedupe_asset_links(task.id)

    links = session.exec(select(CompanyAssetLink)).all()
    assert result.removed_links == 1
    assert len(links) == 1
    assert links[0].asset_id == filing_asset.id
    assert links[0].raw_payload["sources"] == ["enscan_python", "manual_import"]


def test_save_fofa_ports_as_open_tcp_ports(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = NmapScanService(session, config)

    count = service._save_fofa_ports(
        1,
        [FofaPort(ip="8.8.8.8", port=443, protocol="https", host="https://example.com", title="Example", server="nginx")],
    )

    rows = session.exec(select(NmapPort)).all()
    assert count == 1
    assert rows[0].target_ip == "8.8.8.8"
    assert rows[0].protocol == "tcp"
    assert rows[0].port == 443
    assert rows[0].state == "open"
    assert rows[0].service == "https"
    assert rows[0].raw_payload["source"] == "fofa"


def test_fofa_client_preserves_application_protocol_for_service_name():
    config = AppConfig()
    client = FofaClient(config.fofa)

    ports = client._parse_results(
        {"results": [["https://example.cn", "8.8.8.8", "443", "https", "Example", "nginx"]]},
        ["host", "ip", "port", "protocol", "title", "server"],
        "8.8.8.8",
    )

    assert ports[0].protocol == "https"


def test_port_summary_reports_merged_sources(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    logs = []
    service = NmapScanService(session, config, progress=logs.append)
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=443,
            state="open",
            raw_payload={"source": "fofa"},
        )
    )
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.4.4",
            protocol="tcp",
            port=80,
            state="open",
            raw_payload={},
        )
    )
    session.commit()

    service._log_port_summary(1)

    assert any("total=2" in line and "nmap_only=1" in line and "fofa_only=1" in line for line in logs)


def test_nmap_parse_merges_active_evidence_into_existing_fofa_port(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = NmapScanService(session, config)
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=443,
            state="open",
            service="https",
            product="nginx",
            raw_payload={"source": "fofa", "host": "https://example.com", "title": "Example"},
        )
    )
    session.commit()
    port = ET.fromstring(
        '<port protocol="tcp" portid="443">'
        '<state state="open" reason="syn-ack"/>'
        '<service name="https" product="nginx" version="1.25"/>'
        "</port>"
    )

    service._parse_host_ports(session, 1, "8.8.8.8", [port])

    rows = session.exec(select(NmapPort)).all()
    assert len(rows) == 1
    assert rows[0].version == "1.25"
    assert rows[0].raw_payload["sources"] == ["fofa", "nmap"]
    assert rows[0].raw_payload["source"] == "fofa"
    assert rows[0].raw_payload["nmap"]["source"] == "nmap"


def test_fofa_port_validation_targets_only_passive_ports(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=8443,
            state="open",
            raw_payload={"source": "fofa"},
        )
    )
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=443,
            state="open",
            raw_payload={"sources": ["fofa", "nmap"], "fofa": {}, "nmap": {}},
        )
    )
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.4.4",
            protocol="tcp",
            port=8080,
            state="open",
            raw_payload={"source": "fofa"},
        )
    )
    session.commit()

    ports = NmapScanService(session, config)._fofa_ports_by_ip(1, ["8.8.8.8"])

    assert ports == {"8.8.8.8": [8443]}


def test_fofa_validation_parse_keeps_existing_nmap_only_ports(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = NmapScanService(session, config)
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=22,
            state="open",
            raw_payload={"source": "nmap"},
        )
    )
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip="8.8.8.8",
            protocol="tcp",
            port=8443,
            state="open",
            raw_payload={"source": "fofa"},
        )
    )
    session.commit()
    xml_output = tmp_path / "fofa_validation.xml"
    xml_output.write_text(
        '<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="8443">'
        '<state state="open" reason="syn-ack"/>'
        '<service name="https" product="nginx"/>'
        "</port></ports></host></nmaprun>",
        encoding="utf-8",
    )
    run = NmapScanRun(
        scan_task_id=1,
        target_ip=f"{NMAP_FOFA_VALIDATION_PREFIX}8.8.8.8",
        command="nmap",
        xml_output_path=str(xml_output),
        normal_output_path=str(tmp_path / "fofa_validation.txt"),
    )

    service._parse_xml(session, run)

    rows = {row.port: row for row in session.exec(select(NmapPort)).all()}
    assert 22 in rows
    assert rows[8443].raw_payload["sources"] == ["fofa", "nmap"]
    assert rows[8443].raw_payload["nmap"]["source"] == "nmap"


def test_port_targets_include_dns_public_records(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(DnsRecord(scan_task_id=1, fqdn="www.example.cn", root_domain="example.cn", record_type="A", value="8.8.4.4"))
    session.add(DnsRecord(scan_task_id=1, fqdn="manual", root_domain="manual", record_type="A", value="8.8.8.8", raw_payload={"kind": "manual_ip"}))
    session.add(DnsRecord(scan_task_id=1, fqdn="bad.example.cn", root_domain="example.cn", record_type="A", value="198.18.1.1"))
    session.commit()

    by_source = NmapScanService(session, config)._targets_by_source(1)

    assert by_source["dns_public"] == ["8.8.4.4"]
    assert by_source["manual"] == ["8.8.8.8"]


def test_port_targets_write_source_manifest(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        AiAnalysis(
            scan_task_id=1,
            analysis_type="dns_inference",
            status="completed",
            summary="NMAP_TARGET_IPS\n8.8.8.8\nEND_NMAP_TARGET_IPS",
        )
    )
    session.add(DnsRecord(scan_task_id=1, fqdn="www.example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.add(DnsRecord(scan_task_id=1, fqdn="manual", root_domain="manual", record_type="A", value="1.1.1.1", raw_payload={"kind": "manual_ip"}))
    session.commit()
    logs: list[str] = []

    targets = NmapScanService(session, config, progress=logs.append)._targets(1)

    manifest = tmp_path / "data" / "nmap" / "task_1" / "target_sources.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert targets == ["8.8.8.8", "1.1.1.1"]
    assert payload["source_counts"] == {"ai": 1, "manual": 1, "dns_public": 1}
    assert payload["sources_by_ip"]["8.8.8.8"] == ["ai", "dns_public"]
    assert any("target source manifest" in line for line in logs)


def test_fofa_failures_are_logged_without_breaking_nmap_source(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    logs: list[str] = []

    class BrokenFofaClient:
        def __init__(self, _config):
            pass

        def search_ip_ports(self, ip: str):
            raise RuntimeError(f"timeout for {ip}")

    monkeypatch.setattr("assetmap.services.mapping.nmap_scan.FofaClient", BrokenFofaClient)

    NmapScanService(session, config, progress=logs.append)._run_fofa(1, ["8.8.8.8"], required=False)

    payload = json.loads((tmp_path / "data" / "nmap" / "task_1" / "fofa_errors.json").read_text(encoding="utf-8"))
    assert payload["error_count"] == 1
    assert payload["errors"][0]["target"] == "8.8.8.8"
    assert any("[fofa] failures: 1/1" in line for line in logs)


def test_fofa_only_mode_fails_when_all_passive_lookups_fail(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    class BrokenFofaClient:
        def __init__(self, _config):
            pass

        def search_ip_ports(self, ip: str):
            raise RuntimeError(f"timeout for {ip}")

    monkeypatch.setattr("assetmap.services.mapping.nmap_scan.FofaClient", BrokenFofaClient)

    service = NmapScanService(session, config)
    try:
        service._run_fofa(1, ["8.8.8.8"], required=True)
    except RuntimeError as exc:
        assert "FOFA passive lookup failed for all targets" in str(exc)
    else:
        raise AssertionError("expected FOFA-only failure")


def test_port_targets_only_use_dns_inference_ai_analysis(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ScanTask(id=1, target="示例集团有限公司", status="completed"))
    session.add(
        AiAnalysis(
            scan_task_id=1,
            analysis_type="dns_inference",
            status="completed",
            summary="NMAP_TARGET_IPS\n8.8.8.8\nEND_NMAP_TARGET_IPS",
        )
    )
    session.add(
        AiAnalysis(
            scan_task_id=1,
            analysis_type="report_summary",
            status="completed",
            summary="NMAP_TARGET_IPS\n8.8.4.4\nEND_NMAP_TARGET_IPS",
        )
    )
    session.commit()

    by_source = NmapScanService(session, config)._targets_by_source(1)

    assert by_source["ai"] == ["8.8.8.8"]


def test_port_targets_exclude_dns_parking_cname_records(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="old.example.cn",
            root_domain="example.cn",
            record_type="CNAME",
            value="expired.hichina.com",
        )
    )
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="old.example.cn",
            root_domain="example.cn",
            record_type="A",
            value="8.8.8.8",
        )
    )
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="www.example.cn",
            root_domain="example.cn",
            record_type="A",
            value="8.8.4.4",
        )
    )
    session.commit()

    by_source = NmapScanService(session, config)._targets_by_source(1)

    assert by_source["dns_public"] == ["8.8.4.4"]


def test_port_targets_exclude_external_cname_records(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="cdn.example.cn",
            root_domain="example.cn",
            record_type="CNAME",
            value="cdn.vendor.example.com",
        )
    )
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="cdn.example.cn",
            root_domain="example.cn",
            record_type="A",
            value="8.8.8.8",
        )
    )
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="www.example.cn",
            root_domain="example.cn",
            record_type="CNAME",
            value="example.cn",
        )
    )
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="www.example.cn",
            root_domain="example.cn",
            record_type="A",
            value="8.8.4.4",
        )
    )
    session.commit()

    by_source = NmapScanService(session, config)._targets_by_source(1)

    assert by_source["dns_public"] == ["8.8.4.4"]
