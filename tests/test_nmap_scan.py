from pathlib import Path

from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.cli.common import _should_run_stage
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import NmapPort, NmapScanRun, NmapScanTask
from assetmap.services.operations.status import PipelineStatusService
from assetmap.services.mapping.nmap_scan import NMAP_BATCH_TARGET, NMAP_FOFA_VALIDATION_PREFIX, NmapScanService


def test_failed_batch_scan_is_retried_by_normal_resume(tmp_path: Path, monkeypatch):
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
        status="failed",
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    called: list[int] = []
    service = NmapScanService(session, config)
    service._run_one = lambda run_id: called.append(run_id)  # type: ignore[method-assign]

    service._run_batch(1, ["8.8.8.8"])

    assert called == [run.id]
    assert session.get(NmapScanRun, run.id).status == "pending"


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
    config.port_scan.sources_enabled = ["nmap"]
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
                target_ip=NMAP_BATCH_TARGET,
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
