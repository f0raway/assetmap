from pathlib import Path
import json

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import DnsRecord, NmapPort, ServiceAsset, WebProbeResult
from assetmap.services.asset_classifier import AssetClassifierService


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
    config.web_probe.max_workers = 1
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
    captured = []
    service = AssetClassifierService(session, config)
    service._probe_one = lambda scan_task_id, target_ip, port, scheme, host: captured.append((target_ip, port, scheme, host))  # type: ignore[method-assign]

    service._probe_web(1, [port], rerun=True)

    assert ("8.8.8.8", 443, "https", "portal.example.cn") in captured
    assert service._fofa_hosts_by_port(1) == {("8.8.8.8", 443): ["portal.example.cn"]}


def test_probe_hosts_advances_to_unprobed_domain_batch(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.web_probe.max_domains_per_ip = 1
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
        1,
        port,
        {"8.8.8.8": ["a.example.cn", "b.example.cn"]},
        {},
    )

    assert hosts == ["a.example.cn", "b.example.cn"]


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
    captured = []
    service._probe_one = lambda *args: captured.append(args)  # type: ignore[method-assign]

    service._probe_web(1, [port], rerun=True)

    assert captured == []


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
    captured = []
    service = AssetClassifierService(session, config)
    service._probe_one = lambda scan_task_id, target_ip, port, scheme, host: captured.append((scheme, host))  # type: ignore[method-assign]

    service._probe_web(1, [port], rerun=True)

    hosts = {host for _, host in captured}
    assert hosts == {"8.8.8.8", "portal.example.cn"}


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
