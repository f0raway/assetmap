from pathlib import Path
import time

from fastapi.testclient import TestClient

from assetmap.config import load_config, write_sample_config
from assetmap.web.app import LocalJobRunner, create_app, save_config


def _field_paths(fields: list[dict]) -> set[str]:
    paths = set()
    for field in fields:
        if field["type"] == "group":
            paths.update(_field_paths(field["children"]))
        else:
            paths.add(field["path"])
    return paths


def test_web_console_masks_secrets_and_lists_all_config_fields(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    client = TestClient(create_app(config_path))

    page = client.get("/")
    response = client.get("/api/config")

    assert page.status_code == 200
    assert "assetmap 本机控制台" in page.text
    assert response.status_code == 200
    paths = _field_paths(response.json()["fields"])
    assert {"enterprise_discovery.tycid", "enterprise_discovery.control_threshold", "fofa.api_key", "ai.api_key", "tools.nmap_command", "url_discovery.page_hard_timeout_seconds"} <= paths
    assert 'YOUR_OPENAI_API_KEY' not in response.text

    overview = client.get("/api/overview")
    assert overview.status_code == 200
    assert overview.json()["local_only"] is True
    assert isinstance(overview.json()["environment"], list)


def test_web_console_saves_validated_config_without_replacing_secret_or_comments(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    config = load_config(config_path)
    config.ai.api_key = "local-secret"
    save_config(config_path, config)
    client = TestClient(create_app(config_path))

    response = client.put(
        "/api/config",
        json={"enterprise_discovery": {"control_threshold": 0.55}, "ai": {"api_key": ""}},
    )

    assert response.status_code == 200
    saved = load_config(config_path)
    assert saved.enterprise_discovery.control_threshold == 0.55
    assert saved.ai.api_key == "local-secret"
    assert "# 企业发现" in config_path.read_text(encoding="utf-8")


def test_web_console_rejects_scan_without_target(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    client = TestClient(create_app(config_path))

    response = client.post("/api/scans", json={"target": ""})

    assert response.status_code == 422


def test_web_console_rejects_unknown_tool_install(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    client = TestClient(create_app(config_path))

    response = client.post("/api/tools/install", json={"tools": ["unknown-tool"]})

    assert response.status_code == 422


def test_local_job_runner_keeps_progress_and_result(tmp_path: Path):
    runner = LocalJobRunner(tmp_path / "config.yaml")
    completed = []

    job = runner.start("test", "测试任务", lambda progress: (progress("first"), completed.append(True), 42)[2])
    for _ in range(100):
        current = runner.get(job.id)
        if current and current.status != "running":
            break
        time.sleep(0.01)
    current = runner.get(job.id)

    assert current is not None
    assert current.status == "completed"
    assert current.task_id == 42
    assert current.lines == ["first"]
    assert completed == [True]
