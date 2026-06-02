from pathlib import Path

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import AiAnalysis, Company, CompanyAssetLink, DnsQueryStatus, DnsRecord, InternetAsset, SubdomainRecord, SubdomainToolRun
from assetmap.services.subdomain import SubdomainService, _tool_line_dns_values, _tool_line_hostname


def test_clear_dns_results_removes_records_and_statuses(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(DnsRecord(scan_task_id=1, fqdn="example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.add(
        DnsRecord(
            scan_task_id=1,
            fqdn="manual",
            root_domain="manual",
            record_type="A",
            value="8.8.4.4",
            raw_payload={"kind": "manual_ip"},
        )
    )
    session.add(DnsQueryStatus(scan_task_id=1, fqdn="example.cn", root_domain="example.cn", record_type="A", status="completed"))
    session.commit()

    SubdomainService(session, config)._clear_dns_results(1)

    records = session.exec(select(DnsRecord)).all()
    assert len(records) == 1
    assert records[0].raw_payload["kind"] == "manual_ip"
    assert session.exec(select(DnsQueryStatus)).all() == []


def test_dns_ai_analysis_uses_cache_when_payload_unchanged(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.ai.enabled = True
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)
    service._call_ai = lambda ai_config, payload: {  # type: ignore[method-assign]
        "choices": [{"message": {"content": "first analysis"}}]
    }
    session.add(DnsRecord(scan_task_id=1, fqdn="example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.commit()

    service._run_ai_analysis(1)
    service._call_ai = lambda ai_config, payload: (_ for _ in ()).throw(AssertionError("should use cache"))  # type: ignore[method-assign]
    service._run_ai_analysis(1)

    row = session.exec(select(AiAnalysis).where(AiAnalysis.analysis_type == "dns_inference")).one()
    assert row.summary == "first analysis"
    assert row.prompt_json["fingerprint"]


def test_root_domains_are_longest_first_for_specific_matching(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    company = Company(name="Root Co", normalized_name="rootco")
    parent = InternetAsset(asset_type="icp_domain", normalized_identifier="example.cn", display_name="example.cn", raw_payload={})
    child = InternetAsset(asset_type="icp_domain", normalized_identifier="child.example.cn", display_name="child.example.cn", raw_payload={})
    session.add(company)
    session.add(parent)
    session.add(child)
    session.commit()
    session.refresh(company)
    session.refresh(parent)
    session.refresh(child)
    session.add(CompanyAssetLink(task_id=1, company_id=company.id, asset_id=parent.id, source_tool="manual", raw_payload={}))
    session.add(CompanyAssetLink(task_id=1, company_id=company.id, asset_id=child.id, source_tool="manual", raw_payload={}))
    session.commit()

    service = SubdomainService(session, config)

    assert service._root_domains(1) == ["child.example.cn", "example.cn"]
    assert service._root_for_domain(1, "api.child.example.cn") == "child.example.cn"


def test_parse_ksubdomain_chain_output_merges_subdomain_and_dns(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    output = tmp_path / "ksubdomain.txt"
    output.write_text(
        "www.example.cn=>CNAME edge.example.net=>8.8.8.8=>198.18.1.1\n",
        encoding="utf-8",
    )
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="ksubdomain",
            command="ksubdomain",
            output_path=str(output),
            status="completed",
        )
    )
    session.commit()

    SubdomainService(session, config)._parse_tool_outputs(1, ["example.cn"])

    subdomain = session.exec(select(SubdomainRecord)).one()
    records = session.exec(select(DnsRecord).order_by(DnsRecord.record_type, DnsRecord.value)).all()
    assert subdomain.fqdn == "www.example.cn"
    assert subdomain.sources == ["ksubdomain"]
    assert [(row.record_type, row.value) for row in records] == [
        ("A", "8.8.8.8"),
        ("CNAME", "edge.example.net"),
    ]


def test_subdomain_tool_summary_logs_failures(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(SubdomainToolRun(scan_task_id=1, root_domain="example.cn", tool_name="subfinder", command="", output_path="", status="completed"))
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="ksubdomain",
            command="",
            output_path="",
            status="failed",
            error_message="timeout",
        )
    )
    session.commit()
    logs: list[str] = []

    SubdomainService(session, config, progress=logs.append)._log_tool_summary(1)

    assert "[subdomain] tool summary: completed=1, failed=1" in logs
    assert any("ksubdomain:example.cn timeout" in line for line in logs)


def test_interrupted_tool_run_is_detected(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)
    run = SubdomainToolRun(
        scan_task_id=1,
        root_domain="example.cn",
        tool_name="subfinder",
        command="subfinder",
        output_path="out.txt",
        status="failed",
        exit_code=3221225786,
        error_message="^C",
    )

    assert service._is_interrupted_tool_run(run) is True


def test_subdomain_audit_records_tool_and_dns_coverage(tmp_path: Path):
    old_cwd = Path.cwd()
    import os
    os.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    try:
        engine = create_db_and_engine(config.database.url)
        session = get_session(engine)
        session.add(SubdomainToolRun(scan_task_id=1, root_domain="example.cn", tool_name="subfinder", command="", output_path="", status="completed"))
        session.add(SubdomainToolRun(scan_task_id=1, root_domain="child.cn", tool_name="subfinder", command="", output_path="", status="failed", exit_code=3221225786, error_message="^C"))
        session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="www.example.cn", sources=["subfinder"]))
        session.add(DnsRecord(scan_task_id=1, fqdn="example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
        session.add(DnsQueryStatus(scan_task_id=1, fqdn="child.cn", root_domain="child.cn", record_type="A", status="failed", error_message="timeout"))
        session.commit()

        path = SubdomainService(session, config)._write_subdomain_audit(1, ["example.cn", "child.cn"])
        payload = __import__("json").loads(path.read_text(encoding="utf-8"))

        assert payload["tool_run_counts"] == {"subfinder:completed": 1, "subfinder:failed": 1}
        assert payload["interrupted_tool_run_count"] == 1
        assert payload["roots_without_subdomains"] == ["child.cn"]
        assert payload["roots_with_public_ip_count"] == 1
        assert payload["failed_dns_query_count"] == 1
    finally:
        os.chdir(old_cwd)


def test_dns_coverage_summary_logs_gaps(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="www.example.cn", sources=["subfinder"]))
    session.add(DnsRecord(scan_task_id=1, fqdn="example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.add(DnsRecord(scan_task_id=1, fqdn="manual", root_domain="manual", record_type="A", value="1.1.1.1", raw_payload={"kind": "manual_ip"}))
    session.add(DnsQueryStatus(scan_task_id=1, fqdn="child.cn", root_domain="child.cn", record_type="A", status="failed"))
    session.commit()
    logs: list[str] = []

    SubdomainService(session, config, progress=logs.append)._log_dns_coverage_summary(1, ["example.cn", "child.cn"])

    assert "[dns] coverage: roots_with_dns=1/2, roots_with_subdomains=1/2, roots_with_public_ip=1/2, public_ips=1, manual_ips=1, failed_queries=1" in logs
    assert any("roots without discovered subdomains: child.cn" in line for line in logs)
    assert any("roots without public A/AAAA: child.cn" in line for line in logs)


def test_tool_line_parser_understands_chain_output():
    line = "www.example.cn=>CNAME edge.example.net=>8.8.8.8=>198.18.1.1"

    assert _tool_line_hostname(line) == "www.example.cn"
    assert _tool_line_dns_values(line) == [("CNAME", "edge.example.net"), ("A", "8.8.8.8")]


def test_dns_resolution_skips_non_public_a_records(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)

    class FakeItem:
        def __init__(self, value: str) -> None:
            self.value = value

        def to_text(self) -> str:
            return self.value

    class FakeAnswer(list):
        rrset = type("RRSet", (), {"ttl": 60})()

    class FakeResolver:
        def resolve(self, fqdn: str, record_type: str):
            return FakeAnswer([FakeItem("198.18.1.1"), FakeItem("8.8.8.8")])

    service._resolver = lambda: FakeResolver()  # type: ignore[method-assign]

    result = service._resolve_one(1, "example.cn", "example.cn", "A")

    records = session.exec(select(DnsRecord)).all()
    assert result == {"saved": 1, "skipped": 1}
    assert [(row.record_type, row.value) for row in records] == [("A", "8.8.8.8")]
