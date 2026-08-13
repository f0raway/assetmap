import os

from pathlib import Path

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import AiAnalysis, Company, CompanyAssetLink, DnsQueryStatus, DnsRecord, InternetAsset, OriginIpCandidate, SubdomainEnumerationTask, SubdomainRecord, SubdomainToolRun
from assetmap.services.mapping.nmap_scan import extract_ai_marked_service_ips
from assetmap.services.mapping.subdomain import (
    SubdomainService,
    _tool_line_dns_values,
    _tool_line_hostname,
)


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


def test_domain_mapping_rejects_missing_scan_task(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    with __import__("pytest").raises(ValueError, match="Scan task 99 not found"):
        SubdomainService(session, config).run(99)


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
    service._build_origin_candidates(1)

    service._run_ai_analysis(1)
    service._call_ai = lambda ai_config, payload: (_ for _ in ()).throw(AssertionError("should use cache"))  # type: ignore[method-assign]
    service._run_ai_analysis(1)

    row = session.exec(select(AiAnalysis).where(AiAnalysis.analysis_type == "dns_inference")).one()
    assert row.summary == "first analysis"
    assert row.prompt_json["fingerprint"]


def test_dns_ai_analysis_only_approves_high_confidence_candidates(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.ai.enabled = True
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)
    calls: list[dict] = []

    def fake_call(_ai_config, payload):
        calls.append(payload)
        return {"choices": [{"message": {"content": "ORIGIN_IP_DECISIONS\n- 8.8.8.8 | include | high | direct\nEND_ORIGIN_IP_DECISIONS"}}]}

    service._call_ai = fake_call  # type: ignore[method-assign]
    session.add(DnsRecord(scan_task_id=1, fqdn="a.example.cn", root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.add(DnsRecord(scan_task_id=1, fqdn="b.example.cn", root_domain="example.cn", record_type="A", value="1.1.1.1"))
    session.commit()
    service._build_origin_candidates(1)

    service._run_ai_analysis(1)

    row = session.exec(select(AiAnalysis).where(AiAnalysis.analysis_type == "dns_inference")).one()
    assert len(calls) == 1
    assert row.prompt_json["schema_version"] == 4
    candidates = {item.ip: item for item in session.exec(select(OriginIpCandidate)).all()}
    assert candidates["8.8.8.8"].decision == "include"
    assert candidates["1.1.1.1"].decision == "exclude"


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


def test_parse_dnsx_output_merges_subdomain_only(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    output = tmp_path / "dnsx.txt"
    output.write_text("www.example.cn\n", encoding="utf-8")
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="dnsx",
            command="dnsx",
            output_path=str(output),
            status="completed",
        )
    )
    session.commit()

    SubdomainService(session, config)._parse_tool_outputs(1, ["example.cn"])

    subdomain = session.exec(select(SubdomainRecord)).one()
    assert subdomain.fqdn == "www.example.cn"
    assert subdomain.sources == ["dnsx"]
    assert session.exec(select(DnsRecord)).all() == []


def test_subdomain_command_quotes_domain_values(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)

    command = service._format_command(
        "{binary} -d {domain} -o {output}",
        "subfinder",
        "example.cn & unexpected",
        tmp_path / "result.txt",
    )

    if os.name != "nt":
        assert "'example.cn & unexpected'" in command
    else:
        assert '"example.cn & unexpected"' in command


def test_parse_dnsx_skips_large_output_and_removes_pollution(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    monkeypatch.setattr("assetmap.services.mapping.subdomain.SUBDOMAIN_OUTPUT_MAX_LINES", 2)
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    output = tmp_path / "dnsx.txt"
    output.write_text("a.example.cn\nb.example.cn\nc.example.cn\n", encoding="utf-8")
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="dnsx",
            command="dnsx",
            output_path=str(output),
            status="completed",
        )
    )
    session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="old.example.cn", sources=["dnsx"]))
    session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="keep.example.cn", sources=["subfinder", "dnsx"]))
    session.commit()
    logs: list[str] = []

    SubdomainService(session, config, progress=logs.append)._parse_tool_outputs(1, ["example.cn"])

    rows = session.exec(select(SubdomainRecord).order_by(SubdomainRecord.fqdn)).all()
    assert [(row.fqdn, row.sources) for row in rows] == [("keep.example.cn", ["subfinder", "dnsx"])]
    assert any("skipped dnsx output for example.cn" in line for line in logs)
    assert any("removed_tool_only=1" in line for line in logs)


def test_subdomain_tool_summary_logs_failures(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(SubdomainToolRun(scan_task_id=1, root_domain="example.cn", tool_name="subfinder", command="", output_path="", status="completed"))
    session.add(
        SubdomainToolRun(
            scan_task_id=1,
            root_domain="example.cn",
            tool_name="dnsx",
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
    assert any("dnsx:example.cn timeout" in line for line in logs)


def test_subdomain_tool_summary_ignores_disabled_tools(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(SubdomainToolRun(scan_task_id=1, root_domain="example.cn", tool_name="subfinder", command="", output_path="", status="completed"))
    session.add(SubdomainToolRun(scan_task_id=1, root_domain="example.cn", tool_name="retired-tool", command="", output_path="", status="failed", error_message="timeout"))
    session.commit()
    logs: list[str] = []

    SubdomainService(session, config, progress=logs.append)._log_tool_summary(1)

    assert logs == ["[subdomain] tool summary: completed=1"]


def test_subfinder_provider_hint_only_appears_when_subfinder_is_enabled(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    logs: list[str] = []
    service = SubdomainService(session, config, progress=logs.append)

    service._log_subfinder_provider_hint([("dnsx", "")])
    assert logs == []

    service._log_subfinder_provider_hint([("subfinder", "")])
    assert len(logs) == 2
    assert "provider API Key" in logs[0]
    assert "-pc" in logs[1]


def test_subdomain_audit_separates_normal_no_record_from_dns_failure(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(DnsQueryStatus(scan_task_id=1, fqdn="empty.example.cn", root_domain="example.cn", record_type="AAAA", status="completed", error_message="DoH no AAAA answer"))
    session.add(DnsQueryStatus(scan_task_id=1, fqdn="broken.example.cn", root_domain="example.cn", record_type="A", status="failed", error_message="timeout"))
    session.commit()

    path = SubdomainService(session, config)._write_subdomain_audit(1, ["example.cn"])
    payload = __import__("json").loads(path.read_text(encoding="utf-8"))

    assert payload["no_record_dns_query_count"] == 1
    assert payload["failed_dns_query_count"] == 1


def test_ai_failure_reports_retryable_gap(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)
    session.add(OriginIpCandidate(scan_task_id=1, ip="8.8.8.8", decision="pending_ai"))
    session.commit()
    monkeypatch.setattr(service, "_call_ai", lambda *_args: (_ for _ in ()).throw(RuntimeError("gateway unavailable")))

    assert service._run_ai_analysis(1) is False
    assert service._last_ai_error == "gateway unavailable"


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


def test_failed_tool_run_is_retried_by_normal_resume(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    run = SubdomainToolRun(
        scan_task_id=1,
        root_domain="example.cn",
        tool_name="subfinder",
        command="old command",
        output_path="old.txt",
        status="failed",
        error_message="temporary network error",
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    called: list[int] = []
    service = SubdomainService(session, config)
    service._run_tool_job = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._run_enumerators(1, ["example.cn"])

    assert run.id in called
    assert session.get(SubdomainToolRun, run.id).status == "pending"


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

    assert "[dns] coverage: roots_with_dns=1/2, roots_with_subdomains=1/2, roots_with_public_ip=1/2, public_ips=1, manual_ips=1, no_record_queries=0, failed_queries=1" in logs
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
    service._resolve_doh_records = lambda _fqdn, _record_type: {"completed": False, "records": [], "error": "offline"}  # type: ignore[method-assign]

    result = service._resolve_one(1, "example.cn", "example.cn", "A")

    records = session.exec(select(DnsRecord)).all()
    assert result == {"saved": 1, "skipped": 1}
    assert [(row.record_type, row.value) for row in records] == [("A", "8.8.8.8")]


def test_dns_resolution_uses_doh_before_udp(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)

    service._resolver = lambda: (_ for _ in ()).throw(AssertionError("UDP DNS should not be used"))  # type: ignore[method-assign]
    service._resolve_doh_records = lambda _fqdn, _record_type: {  # type: ignore[method-assign]
        "completed": True,
        "records": [{"value": "47.101.48.251", "ttl": 120, "endpoint": "https://dns.google/resolve"}],
        "error": None,
    }

    result = service._resolve_one(1, "www.example.cn", "example.cn", "A")

    records = session.exec(select(DnsRecord)).all()
    assert result == {"saved": 1, "skipped": 0}
    assert [(row.record_type, row.value, row.ttl, row.raw_payload["source"]) for row in records] == [
        ("A", "47.101.48.251", 120, "doh")
    ]


def test_dns_resolution_skips_polluted_doh_ip(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = SubdomainService(session, config)
    service._resolve_doh_records = lambda _fqdn, _record_type: {  # type: ignore[method-assign]
        "completed": True,
        "records": [{"value": "198.18.0.136", "ttl": 120, "endpoint": "https://dns.google/resolve"}],
        "error": None,
    }

    result = service._resolve_one(1, "www.example.cn", "example.cn", "A")

    assert result == {"saved": 0, "skipped": 1}
    assert session.exec(select(DnsRecord)).all() == []


def test_discovered_subdomains_are_logged_before_dns(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="www.example.cn", sources=["subfinder"]))
    session.add(SubdomainRecord(scan_task_id=1, root_domain="example.cn", fqdn="api.example.cn", sources=["dnsx"]))
    session.commit()
    logs: list[str] = []

    SubdomainService(session, config, progress=logs.append)._log_discovered_subdomains(1)

    output = tmp_path / "data" / "subdomains" / "task_1" / "discovered_subdomains.txt"
    assert output.read_text(encoding="utf-8").splitlines() == ["api.example.cn", "www.example.cn"]
    assert "[subdomain] discovered subdomains before DNS: 2" in logs
    assert any("api.example.cn" in line and "www.example.cn" in line for line in logs)
