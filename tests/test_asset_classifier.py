from pathlib import Path
import json

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import DnsRecord, NmapPort, ServiceAsset, WebProbeResult
from assetmap.services.identification.asset_classifier import AssetClassifierService


def test_web_asset_prefers_final_url(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    port = NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=443, state="open")
    probe = WebProbeResult(
        scan_task_id=1,
        target_ip="8.8.8.8",
        port=443,
        scheme="https",
        host="www.example.cn",
        url="https://www.example.cn:443/",
        status="responded",
        http_status=200,
        final_url="https://www.example.cn/login",
        title="示例系统",
    )

    service._save_web_asset(1, port, [probe])

    row = session.exec(select(ServiceAsset)).one()
    assert row.representative_url == "https://www.example.cn/login"


def test_httpx_json_result_is_saved_as_a_web_probe(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    output = tmp_path / "httpx.jsonl"
    url = "https://portal.example.cn:443/"
    output.write_text(
        json.dumps({"input": url, "url": "https://portal.example.cn/login", "status_code": 200,
                    "title": "统一门户", "webserver": "nginx", "content_type": "text/html",
                    "content_length": 1234, "tech": ["Vue"], "hashes": {"sha256": "abc"}}) + "\n",
        encoding="utf-8",
    )

    saved = AssetClassifierService(session, config)._save_httpx_results(
        1, output, {url: ("8.8.8.8", 443, "https", "portal.example.cn")}
    )

    result = session.exec(select(WebProbeResult)).one()
    assert saved == 1
    assert result.status == "responded"
    assert result.final_url == "https://portal.example.cn/login"
    assert result.tech_stack == ["Vue"]
    assert result.raw_headers["probe_source"] == "projectdiscovery_httpx"


def test_legacy_python_probe_checkpoint_is_replaced(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebProbeResult(
            scan_task_id=1,
            target_ip="8.8.8.8",
            port=80,
            scheme="http",
            host="8.8.8.8",
            url="http://8.8.8.8:80/",
            status="responded",
            raw_headers={"server": "legacy"},
        )
    )
    session.commit()

    checkpoint = AssetClassifierService(session, config)._httpx_checkpoint(1, "8.8.8.8", 80, "http", "8.8.8.8")

    assert checkpoint is None
    assert session.exec(select(WebProbeResult)).all() == []


def test_classifier_logs_probe_and_service_summary(tmp_path: Path):
    old_cwd = Path.cwd()
    import os
    os.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    try:
        engine = create_db_and_engine(config.database.url)
        session = get_session(engine)
        logs = []
        service = AssetClassifierService(session, config, progress=logs.append)
        session.add(
            WebProbeResult(
                scan_task_id=1,
                target_ip="8.8.8.8",
                port=80,
                scheme="http",
                host="8.8.8.8",
                url="http://8.8.8.8/",
                status="responded",
                http_status=200,
            )
        )
        session.add(
            WebProbeResult(
                scan_task_id=1,
                target_ip="8.8.4.4",
                port=8080,
                scheme="http",
                host="8.8.4.4",
                url="http://8.8.4.4:8080/",
                status="failed",
                error_message="timeout",
            )
        )
        session.add(ServiceAsset(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=80, asset_kind="web"))
        session.add(ServiceAsset(scan_task_id=1, target_ip="8.8.4.4", protocol="tcp", port=8080, asset_kind="non_web", service="tcp", product="nginx"))
        session.commit()

        service._log_web_probe_summary(1)
        service._log_service_summary(1)

        probe_audit = json.loads((tmp_path / "data" / "classify" / "task_1" / "web_probe_audit.json").read_text(encoding="utf-8"))
        service_audit = json.loads((tmp_path / "data" / "classify" / "task_1" / "service_classification_audit.json").read_text(encoding="utf-8"))
        assert any("responded=1" in line for line in logs)
        assert any("web=1" in line for line in logs)
        assert probe_audit["failed"] == 1
        assert service_audit["kind_counts"] == {"non_web": 1, "web": 1}
        assert service_audit["host_mode_counts"] == {"unknown": 2}
        assert service_audit["review_candidate_count"] == 1
        assert service_audit["web_like_review_candidates"][0]["port"] == 8080
        assert service_audit["services"][0]["endpoint"] == "8.8.4.4:8080"
        assert "asset_kind" in service_audit["services"][0]
    finally:
        os.chdir(old_cwd)


def test_fofa_host_is_used_as_web_probe_candidate(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    port = NmapPort(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=443,
        state="open",
        raw_payload={"source": "fofa", "host": "https://portal.example.cn/login"},
    )
    session.add(port)
    session.commit()
    service = AssetClassifierService(session, config)
    hosts = service._probe_hosts(port, {}, service._fofa_hosts_by_port(1))

    assert "portal.example.cn" in hosts
    assert service._fofa_hosts_by_port(1) == {("8.8.8.8", 443): ["portal.example.cn"]}


def test_probe_hosts_returns_all_unprobed_domains_without_a_batch_limit(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    port = NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=80, state="open")
    session.add(
        WebProbeResult(
            scan_task_id=1,
            target_ip="8.8.8.8",
            port=80,
            scheme="http",
            host="8.8.8.8",
            url="http://8.8.8.8/",
        )
    )
    session.add(
        WebProbeResult(
            scan_task_id=1,
            target_ip="8.8.8.8",
            port=80,
            scheme="https",
            host="8.8.8.8",
            url="https://8.8.8.8/",
        )
    )
    session.commit()

    hosts = AssetClassifierService(session, config)._probe_hosts(
        port,
        {"8.8.8.8": ["a.example.cn", "b.example.cn"]},
        {},
    )

    assert hosts == ["8.8.8.8", "a.example.cn", "b.example.cn"]


def test_web_probe_runs_httpx_primary_then_fallback_batches(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    port = NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=80, state="open")
    captured = []
    service = AssetClassifierService(session, config)
    service._run_httpx_batch = lambda task_id, phase, jobs: captured.append((phase, jobs))  # type: ignore[method-assign]

    service._probe_web(
        1,
        [port],
        rerun=True,
    )

    assert captured == [
        ("primary", [("8.8.8.8", 80, "http", "8.8.8.8")]),
        ("fallback", [("8.8.8.8", 80, "https", "8.8.8.8")]),
    ]


def test_standard_web_port_skips_fallback_after_primary_response(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    captured = []

    def responded(task_id, phase, jobs):
        captured.append((phase, jobs))
        if phase == "primary":
            for target_ip, port, scheme, host in jobs:
                service._save_httpx_probe(task_id, (target_ip, port, scheme, host), {"status_code": 200})

    service._run_httpx_batch = responded  # type: ignore[method-assign]
    service._probe_web(
        1,
        [
            NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=80, state="open"),
            NmapPort(scan_task_id=1, target_ip="1.1.1.1", protocol="tcp", port=443, state="open"),
        ],
        rerun=True,
    )

    assert captured == [
        ("primary", [("8.8.8.8", 80, "http", "8.8.8.8"), ("1.1.1.1", 443, "https", "1.1.1.1")])
    ]


def test_http_400_tls_mismatch_triggers_https_fallback(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    captured = []

    def tls_mismatch(task_id, phase, jobs):
        captured.append((phase, jobs))
        if phase == "primary":
            for job in jobs:
                service._save_httpx_probe(
                    task_id,
                    job,
                    {
                        "status_code": 400,
                        "title": "400 The plain HTTP request was sent to HTTPS port",
                    },
                )

    service._run_httpx_batch = tls_mismatch  # type: ignore[method-assign]
    service._probe_web(
        1,
        [NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=21082, state="open", service="https")],
        rerun=True,
    )

    assert captured == [
        ("primary", [("8.8.8.8", 21082, "http", "8.8.8.8")]),
        ("fallback", [("8.8.8.8", 21082, "https", "8.8.8.8")]),
    ]
    primary = session.exec(select(WebProbeResult).where(WebProbeResult.scheme == "http")).one()
    assert primary.status == "protocol_mismatch"


def test_protocol_mismatch_is_not_classified_as_a_web_service(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    port = NmapPort(scan_task_id=1, target_ip="8.8.8.8", protocol="tcp", port=21082, state="open", service="https")
    service._save_httpx_probe(
        1,
        ("8.8.8.8", 21082, "http", "8.8.8.8"),
        {"status_code": 400, "title": "The plain HTTP request was sent to HTTPS port"},
    )

    service._classify(1, [port])

    asset = session.exec(select(ServiceAsset)).one()
    assert asset.asset_kind == "non_web"


def test_obvious_non_web_ports_are_not_web_probed(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    port = NmapPort(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=22,
        state="open",
        service="ssh",
    )
    assert service._should_probe_web(port) is False


def test_nonstandard_port_uses_fofa_host_without_dns_fanout(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    port = NmapPort(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=2075,
        state="open",
        service="https",
        raw_payload={"source": "fofa", "host": "https://portal.example.cn:2075"},
    )
    session.add(port)
    for host in ("a.example.cn", "b.example.cn", "c.example.cn"):
        session.add(DnsRecord(scan_task_id=1, fqdn=host, root_domain="example.cn", record_type="A", value="8.8.8.8"))
    session.commit()
    service = AssetClassifierService(session, config)
    hosts = service._probe_hosts(port, service._domains_by_ip(1), service._fofa_hosts_by_port(1))
    assert set(hosts) == {"8.8.8.8", "portal.example.cn"}


def test_failed_active_probe_keeps_fofa_passive_web_asset(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    port = NmapPort(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=9980,
        state="open",
        service="tcp",
        product="nginx/1.20.1",
        raw_payload={
            "source": "fofa",
            "host": "8.8.8.8:9980",
            "title": "工单系统",
            "server": "nginx/1.20.1",
            "raw": {
                "host": "8.8.8.8:9980",
                "protocol": "http",
                "title": "工单系统",
                "server": "nginx/1.20.1",
            },
        },
    )
    probes = [
        WebProbeResult(
            scan_task_id=1,
            target_ip="8.8.8.8",
            port=9980,
            scheme="http",
            host="8.8.8.8",
            url="http://8.8.8.8:9980/",
            status="failed",
            error_message="Server disconnected without sending a response.",
        )
    ]

    service._save_non_web_asset(1, port, probes)

    row = session.exec(select(ServiceAsset)).one()
    assert row.asset_kind == "web"
    assert row.host_mode == "passive_fofa"
    assert row.representative_url == "http://8.8.8.8:9980/"
    assert row.title == "工单系统"
    assert row.evidence["passive_web_source"] == "fofa"


def test_invalid_fofa_host_port_falls_back_to_verified_port(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = AssetClassifierService(session, config)
    port = NmapPort(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=8443,
        state="open",
    )

    url = service._passive_web_url("https://portal.example.cn:not-a-port", "https", port.port)

    assert url == "https://portal.example.cn:8443/"
