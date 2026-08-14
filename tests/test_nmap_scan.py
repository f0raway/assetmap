from pathlib import Path
import json
import xml.etree.ElementTree as ET

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.cli.common import _should_run_stage
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import NmapPort, NmapScanRun, NmapScanTask, StageWorkUnit
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.mapping.nmap_scan import (
    NMAP_BATCH_TARGET,
    NMAP_FOFA_VALIDATION_PREFIX,
    NMAP_TARGET_PREFIX,
    NmapScanService,
)


def test_interrupted_legacy_batch_migrates_to_a_per_ip_recovery_job(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    run = NmapScanRun(
        scan_task_id=1,
        target_ip=NMAP_BATCH_TARGET,
        command="old command",
        xml_output_path="old.xml",
        normal_output_path="old.txt",
        status="interrupted",
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    called: list[int] = []
    service = NmapScanService(session, config)
    service._run_one = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._run_batch(1, ["8.8.8.8"])

    assert len(called) == 1
    recovered = session.get(NmapScanRun, called[0])
    assert recovered is not None
    assert recovered.target_ip == f"{NMAP_TARGET_PREFIX}8.8.8.8"
    assert session.get(NmapScanRun, run.id).status == "interrupted"


def test_port_stage_without_confirmed_origins_completes_with_a_reviewable_gap(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    logs: list[str] = []

    task_id = NmapScanService(session, config, progress=logs.append).run(1)

    task = session.get(NmapScanTask, task_id)
    assert task is not None
    assert task.status == "completed_with_gaps"
    assert task.targets == []
    assert "No confirmed origin IPs found" in (task.error_message or "")
    assert any("[port] skipped: no confirmed origin IPs" in line for line in logs)


def test_completed_per_ip_nmap_unit_is_not_repeated_on_resume(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    output = tmp_path / "8_8_8_8.xml"
    output.write_text("<nmaprun/>", encoding="utf-8")
    run = NmapScanRun(
        scan_task_id=1,
        target_ip=f"{NMAP_TARGET_PREFIX}8.8.8.8",
        command="old command",
        xml_output_path=str(output),
        normal_output_path=str(tmp_path / "8_8_8_8.nmap"),
        status="completed",
    )
    session.add(run)
    session.commit()
    service = NmapScanService(session, config)
    run = service._get_or_create_target_run(1, "8.8.8.8", config.data_path("nmap", "task_1"))
    from assetmap.services.runtime.work_units import WorkUnitTracker

    tracker = WorkUnitTracker(session, 1, "port-scan")
    unit, _ = tracker.get_or_create(
        "nmap_full_port",
        "8.8.8.8",
        {"policy": "nmap-full-port-per-ip-v1", "target": "8.8.8.8", "command": run.command},
    )
    tracker.complete(unit, output_path=output)
    called: list[int] = []
    service._run_one = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._run_batch(1, ["8.8.8.8"])

    assert called == []


def test_fofa_zero_result_is_saved_and_not_queried_again(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    calls: list[str] = []

    class EmptyFofaClient:
        def __init__(self, _config):
            pass

        def set_progress(self, _progress):
            pass

        def search_ip_ports(self, ip: str):
            calls.append(ip)
            return []

    monkeypatch.setattr("assetmap.services.mapping.nmap_scan.FofaClient", EmptyFofaClient)
    service = NmapScanService(session, config)
    service._run_fofa(1, ["8.8.8.8"])
    service._run_fofa(1, ["8.8.8.8"])

    assert calls == ["8.8.8.8"]
    unit = session.exec(select(StageWorkUnit).where(StageWorkUnit.unit_key == "8.8.8.8")).one()
    assert unit.status == "completed"
    assert unit.details["ports_returned"] == 0


def test_preflight_rechecks_when_target_list_changes(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = NmapScanService(session, config)
    output_dir = config.data_path("nmap", "task_1")
    output_dir.mkdir(parents=True)
    xml = output_dir / "preflight.xml"
    xml.write_text("<nmaprun/>", encoding="utf-8")
    target_file = output_dir / "preflight_targets.txt"
    target_file.write_text("8.8.8.8\n", encoding="utf-8")
    run = service._get_or_create_preflight_run(1, target_file, output_dir)
    run.status = "completed"
    session.add(run)
    session.commit()
    from assetmap.services.runtime.work_units import WorkUnitTracker

    tracker = WorkUnitTracker(session, 1, "port-scan")
    unit, _ = tracker.get_or_create(
        "nmap_preflight",
        "all-targets",
        {
            "policy": "nmap-accept-all-preflight-v1",
            "targets": ["8.8.8.8"],
            "sentinel_ports": [1, 22, 80, 443, 3306, 8080, 49152, 65535],
            "command": run.command,
        },
    )
    tracker.complete(unit, output_path=xml)
    called: list[int] = []
    service._run_one = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._preflight_targets(1, ["8.8.8.8", "1.1.1.1"])

    assert called == [run.id]


def test_batch_command_always_enables_service_version_detection():
    assert NmapScanService._ensure_service_version_detection("nmap -Pn -p- -iL targets.txt") == (
        "nmap -Pn -p- -iL targets.txt -sV --version-intensity 5 --script-timeout 60s --stats-every 15s"
    )
    command = "nmap -Pn -sV -p- -iL targets.txt"
    assert NmapScanService._ensure_service_version_detection(command) == f"{command} --script-timeout 60s --stats-every 15s"


def test_run_one_streams_nmap_output_and_does_not_set_a_timeout(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    run = NmapScanRun(
        scan_task_id=1,
        target_ip=NMAP_BATCH_TARGET,
        command="nmap test",
        xml_output_path=str(tmp_path / "nmap.xml"),
        normal_output_path=str(tmp_path / "nmap.txt"),
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    calls = {}

    class FakeProcess:
        stdout = iter(["Starting Nmap\\n", "Stats: 2 hosts completed\\n"])

        def wait(self, *args, **kwargs):
            return 0

        def poll(self):
            return 0

    def fake_popen(*args, **kwargs):
        calls["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr("assetmap.services.mapping.nmap_scan.subprocess.Popen", fake_popen)
    logs: list[str] = []

    NmapScanService(session, config, progress=logs.append)._run_one(run.id)

    session.expire_all()
    saved = session.get(NmapScanRun, run.id)
    assert saved is not None and saved.status == "completed"
    assert "Stats: 2 hosts completed" in saved.stdout
    assert any("Stats: 2 hosts completed" in message for message in logs)
    assert "timeout" not in calls["kwargs"]


def test_preflight_detects_tcp_accept_all_target_from_sentinel_ports(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    service = NmapScanService(get_session(create_db_and_engine(config.database.url)), config)
    ports = (1, 22, 80, 443, 3306, 8080, 49152, 65535)
    xml = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/></port>'
        for port in ports
    )
    path = tmp_path / "preflight.xml"
    path.write_text(f'<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/><ports>{xml}</ports></host></nmaprun>', encoding="utf-8")

    assert service._preflight_accept_all_targets(path) == ["8.8.8.8"]


def test_parser_discards_mass_tcpwrapped_ports_and_keeps_fofa_evidence(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}")).bind_config_path(tmp_path / "config.yaml")
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
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
    session.commit()
    ports = [
        ET.fromstring(
            f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
            '<service name="tcpwrapped" method="probed" conf="8"/></port>'
        )
        for port in range(1, 1025)
    ]

    NmapScanService(session, config)._parse_host_ports(session, 1, "8.8.8.8", ports)

    rows = session.exec(select(NmapPort).where(NmapPort.scan_task_id == 1)).all()
    assert len(rows) == 1
    assert rows[0].raw_payload == {"source": "fofa"}
    audit = json.loads((tmp_path / "data" / "nmap" / "task_1" / "port_anomaly_audit.json").read_text(encoding="utf-8"))
    assert audit["parser_fallback"][0]["target_ip"] == "8.8.8.8"
    assert audit["parser_fallback"][0]["open_tcp_ports"] == 1024


def test_failed_fofa_validation_is_retried_by_normal_resume(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    target = "8.8.8.8"
    session.add(
        NmapPort(
            scan_task_id=1,
            target_ip=target,
            protocol="tcp",
            port=8443,
            state="open",
            raw_payload={"source": "fofa"},
        )
    )
    run = NmapScanRun(
        scan_task_id=1,
        target_ip=f"{NMAP_FOFA_VALIDATION_PREFIX}{target}",
        command="old command",
        xml_output_path="old.xml",
        normal_output_path="old.txt",
        status="failed",
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    called: list[int] = []
    service = NmapScanService(session, config)
    service._run_one = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._validate_fofa_ports(1, [target])

    assert called == [run.id]
    assert session.get(NmapScanRun, run.id).status == "pending"


def test_failed_active_run_is_exposed_for_normal_pipeline_retry(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = NmapScanService(session, config)
    service._targets = lambda scan_task_id: ["8.8.8.8"]  # type: ignore[method-assign]
    service._run_fofa = lambda *args, **kwargs: None  # type: ignore[method-assign]
    service._validate_fofa_ports = lambda *args, **kwargs: None  # type: ignore[method-assign]

    def fail_batch(scan_task_id, targets, rerun=False):
        session.add(
            NmapScanRun(
                scan_task_id=scan_task_id,
                target_ip=f"{NMAP_TARGET_PREFIX}8.8.8.8",
                command="nmap",
                xml_output_path="out.xml",
                normal_output_path="out.txt",
                status="failed",
                error_message="binary missing",
            )
        )
        session.commit()

    service._run_batch = fail_batch  # type: ignore[method-assign]

    service.run(1)

    task = session.exec(select(NmapScanTask).where(NmapScanTask.scan_task_id == 1)).one()
    assert task.status == "completed"
    stage_status = dict((name, status) for name, status, _ in PipelineStatusService(session)._stages(1, PipelineStatusService(session)._counts(1)))
    assert stage_status["port-scan"] == "completed_with_errors"
    assert _should_run_stage(stage_status, "port-scan") is True
