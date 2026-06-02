from pathlib import Path
import json

import httpx
from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import ServiceAsset, WebEntrypoint, WebProbeResult
from assetmap.services.url_discovery import UrlDiscoveryService, _clean_ai_text, _looks_blank, _page_state_summary


def test_seed_web_probe_as_entrypoint(tmp_path: Path):
    config = AppConfig(
        database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"),
    )
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service_asset = ServiceAsset(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=443,
        asset_kind="web",
        representative_url="https://portal.example.cn/",
        domains=["portal.example.cn"],
    )
    probe = WebProbeResult(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=443,
        scheme="https",
        host="portal.example.cn",
        url="https://portal.example.cn:443/",
        status="responded",
        http_status=200,
        final_url="https://portal.example.cn/login",
        title="统一门户",
        body_hash="abc",
        body_length=1234,
        tech_stack=["Vue"],
    )
    session.add(service_asset)
    session.add(probe)
    session.commit()

    service = UrlDiscoveryService(session, config)
    saved = service._seed_entrypoints(1)

    rows = session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == 1)).all()
    assert saved == 1
    assert len(rows) == 1
    assert rows[0].normalized_url == "https://portal.example.cn/login"
    assert rows[0].title == "统一门户"
    assert rows[0].evidence["source"] == "web_probe"


def test_seed_entrypoint_links_ip_site_probe_to_service_asset(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service_asset = ServiceAsset(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=8443,
        asset_kind="web",
        host_mode="ip_site",
        representative_url="https://203.0.113.10:8443/",
    )
    probe = WebProbeResult(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=8443,
        scheme="https",
        host="203.0.113.10",
        url="https://203.0.113.10:8443/",
        status="responded",
        http_status=200,
        final_url="https://203.0.113.10:8443/login",
    )
    session.add(service_asset)
    session.add(probe)
    session.commit()

    UrlDiscoveryService(session, config)._seed_entrypoints(1)

    row = session.exec(select(WebEntrypoint)).one()
    assert row.service_asset_id == service_asset.id


def test_seed_entrypoint_canonicalizes_plain_http_on_https_port(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    old_entry = WebEntrypoint(
        scan_task_id=1,
        host="portal.example.cn",
        url="http://portal.example.cn:443/",
        normalized_url="http://portal.example.cn:443/",
        final_url="http://portal.example.cn:443/",
        port=443,
        evidence={"source": "web_probe", "merged_from": ["http://old.example.cn:443/"]},
    )
    probe = WebProbeResult(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=443,
        scheme="http",
        host="portal.example.cn",
        url="http://portal.example.cn:443/",
        status="responded",
        http_status=400,
        title="400 The plain HTTP request was sent to HTTPS port",
    )
    session.add(old_entry)
    session.add(probe)
    session.commit()

    saved = UrlDiscoveryService(session, config)._seed_entrypoints(1)

    rows = session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == 1)).all()
    assert saved == 1
    assert len(rows) == 1
    assert rows[0].normalized_url == "https://portal.example.cn/"
    assert rows[0].url == "https://portal.example.cn/"
    assert rows[0].final_url == "https://portal.example.cn/"
    assert rows[0].evidence["merged_from"] == ["http://portal.example.cn:443/", "http://old.example.cn:443/"]


def test_seed_service_asset_entrypoint_when_probe_status_is_skipped(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service_asset = ServiceAsset(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=8888,
        asset_kind="web",
        representative_url="http://portal.example.cn:8888/",
        domains=["portal.example.cn"],
        http_status=404,
        title="404 Not Found",
    )
    probe = WebProbeResult(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=8888,
        scheme="http",
        host="portal.example.cn",
        url="http://portal.example.cn:8888/",
        status="responded",
        http_status=404,
        title="404 Not Found",
    )
    session.add(service_asset)
    session.add(probe)
    session.commit()

    saved = UrlDiscoveryService(session, config)._seed_entrypoints(1)

    rows = session.exec(select(WebEntrypoint).where(WebEntrypoint.scan_task_id == 1)).all()
    assert saved == 1
    assert len(rows) == 1
    assert rows[0].service_asset_id == service_asset.id
    assert rows[0].evidence["source"] == "service_asset"


def test_parse_visual_json_from_markdown_block(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = UrlDiscoveryService(session, config)

    result = service._parse_json(
        '```json\n{"system_name":"能管平台","site_purpose":"能源管理","confidence":0.9}\n```'
    )

    assert result["system_name"] == "能管平台"
    assert result["site_purpose"] == "能源管理"


def test_ai_http_error_message_is_concise(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service = UrlDiscoveryService(session, config)
    request = httpx.Request("POST", "https://example.test/v1/chat/completions")
    response = httpx.Response(404, request=request, text='{"error":"model not found"}')
    exc = httpx.HTTPStatusError("not found", request=request, response=response)

    message = service._error_message(exc)

    assert message.startswith("AI HTTP 404")
    assert "model not found" in message


def test_pending_entrypoints_skip_recorded_visual_errors(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="example.cn",
        url="https://example.cn/",
        normalized_url="https://example.cn/",
        evidence={"visual_analysis_error": "timeout"},
    )
    session.add(entry)
    session.commit()

    service = UrlDiscoveryService(session, config)

    assert service._pending_entrypoints(1, rerun=False) == []
    assert len(service._pending_entrypoints(1, rerun=False, retry_failed=True)) == 1
    assert len(service._pending_entrypoints(1, rerun=True)) == 1


def test_pending_entrypoints_retry_probe_fallbacks(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="fallback.example.cn",
            url="https://fallback.example.cn/",
            normalized_url="https://fallback.example.cn/",
            evidence={"visual_analysis": {"analysis_method": "http_probe_fallback"}},
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="ok.example.cn",
            url="https://ok.example.cn/",
            normalized_url="https://ok.example.cn/",
            evidence={"visual_analysis": {"analysis_method": "screenshot_ai"}},
        )
    )
    session.commit()

    service = UrlDiscoveryService(session, config)

    assert service._pending_entrypoints(1, rerun=False) == []
    pending = service._pending_entrypoints(1, rerun=False, retry_failed=True)
    assert [row.host for row in pending] == ["fallback.example.cn"]


def test_visual_summary_counts_success_and_failed(tmp_path: Path):
    old_cwd = Path.cwd()
    import os
    os.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    try:
        engine = create_db_and_engine(config.database.url)
        session = get_session(engine)
        session.add(
            WebEntrypoint(
                scan_task_id=1,
                host="ok.example.cn",
                url="https://ok.example.cn/",
                normalized_url="https://ok.example.cn/",
                evidence={"visual_analysis": {"system_name": "OK", "screenshot_path": "ok.png"}},
            )
        )
        session.add(
            WebEntrypoint(
                scan_task_id=1,
                host="fail.example.cn",
                url="https://fail.example.cn/",
                normalized_url="https://fail.example.cn/",
                evidence={"visual_analysis_error": "timeout"},
            )
        )
        session.commit()
        logs = []

        UrlDiscoveryService(session, config, progress=logs.append)._log_visual_summary(1)
        audit = json.loads((tmp_path / "data" / "url_discovery" / "task_1" / "visual_analysis_audit.json").read_text(encoding="utf-8"))
        refreshed = session.exec(select(WebEntrypoint).where(WebEntrypoint.host == "ok.example.cn")).one()

        assert any(line.endswith("total=2, ok=1, failed=1, pending=0") for line in logs)
        assert audit["method_counts"] == {"failed": 1, "screenshot_ai": 1}
        assert audit["failed_samples"][0]["url"] == "https://fail.example.cn/"
        assert refreshed.evidence["visual_analysis"]["analysis_method"] == "screenshot_ai"
    finally:
        os.chdir(old_cwd)


def test_clean_ai_text_removes_replacement_characters():
    value = _clean_ai_text({"title": "登录�系统", "items": ["a�b"]})

    assert value == {"title": "登录系统", "items": ["ab"]}


def test_blank_page_state_detection():
    blank = {"title": "", "textLength": 0, "visibleElements": 0, "mediaElements": 0, "formElements": 0, "bodyHeight": 20, "viewportHeight": 900}
    login = {"title": "统一门户", "textLength": 2, "visibleElements": 1, "mediaElements": 0, "formElements": 1, "bodyHeight": 900, "viewportHeight": 900}

    assert _looks_blank(blank) is True
    assert _looks_blank(login) is False
    assert "visible=0" in _page_state_summary(blank)


def test_clear_stale_visual_errors_keeps_successful_analysis(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="ok.example.cn",
        url="https://ok.example.cn/",
        normalized_url="https://ok.example.cn/",
        evidence={
            "visual_analysis": {"system_name": "OK"},
            "visual_analysis_error": "old timeout",
            "visual_analysis_error_at": "2026-01-01T00:00:00Z",
            "visual_analysis_screenshot_path": "old.png",
        },
    )
    session.add(entry)
    session.commit()

    UrlDiscoveryService(session, config)._clear_stale_visual_errors(1)
    refreshed = session.get(WebEntrypoint, entry.id)

    assert refreshed.evidence == {"visual_analysis": {"system_name": "OK"}}


def test_pending_entrypoints_prioritizes_useful_pages(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    config.url_discovery.visual_max_pages = 2
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="bad.example.cn",
            url="http://bad.example.cn/",
            normalized_url="http://bad.example.cn/",
            http_status=404,
            title="404 Not Found",
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="portal.example.cn",
            url="https://portal.example.cn/",
            normalized_url="https://portal.example.cn/",
            http_status=200,
            title="统一门户",
            body_length=2000,
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="login.example.cn",
            url="https://login.example.cn/",
            normalized_url="https://login.example.cn/",
            http_status=200,
            title="登录系统",
            body_length=1500,
        )
    )
    session.commit()

    pending = UrlDiscoveryService(session, config)._pending_entrypoints(1, rerun=False)

    assert [row.host for row in pending] == ["portal.example.cn", "login.example.cn"]


def test_probe_fallback_saves_visual_analysis_when_screenshot_fails(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="portal.example.cn",
        url="https://portal.example.cn/",
        normalized_url="https://portal.example.cn/",
        http_status=200,
        title="统一门户",
        server="nginx",
    )
    session.add(entry)
    session.commit()

    saved = UrlDiscoveryService(session, config)._save_probe_fallback(entry.id, "timeout")
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.evidence["visual_analysis"]["analysis_method"] == "http_probe_fallback"
    assert refreshed.evidence["visual_analysis"]["website_title"] == "统一门户"


def test_ai_fallback_keeps_screenshot_and_probe_title(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    screenshot = tmp_path / "portal.png"
    screenshot.write_bytes(b"png")
    entry = WebEntrypoint(
        scan_task_id=1,
        host="portal.example.cn",
        url="https://portal.example.cn/",
        normalized_url="https://portal.example.cn/",
        http_status=200,
        title="统一门户",
        tech_stack=["nginx"],
    )
    session.add(entry)
    session.commit()

    saved = UrlDiscoveryService(session, config)._save_ai_fallback(
        entry.id,
        "AI HTTP 404 Not Found",
        screenshot=screenshot,
        final_url="https://portal.example.cn/login",
    )
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.final_url == "https://portal.example.cn/login"
    visual = refreshed.evidence["visual_analysis"]
    assert visual["analysis_method"] == "http_probe_fallback"
    assert visual["page_type"] == "ai_analysis_fallback"
    assert visual["screenshot_path"] == str(screenshot)
    assert visual["ai_error"] == "AI HTTP 404 Not Found"
    assert "visual_analysis_error" not in refreshed.evidence


def test_screenshot_candidates_correct_plain_http_on_https_port(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="portal.example.cn",
        url="http://portal.example.cn:443/",
        normalized_url="http://portal.example.cn:443/",
        final_url="http://portal.example.cn:443/login",
        port=443,
        title="400 The plain HTTP request was sent to HTTPS port",
    )

    candidates = UrlDiscoveryService(session, config)._screenshot_candidate_urls(entry)

    assert candidates[0] == "https://portal.example.cn/login"
    assert "http://portal.example.cn:443/login" in candidates


def test_screenshot_candidates_preserve_non_https_hint_url(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="portal.example.cn",
        url="http://portal.example.cn:8080/",
        normalized_url="http://portal.example.cn:8080/",
        port=8080,
        title="统一门户",
    )

    candidates = UrlDiscoveryService(session, config)._screenshot_candidate_urls(entry)

    assert candidates == ["http://portal.example.cn:8080/"]


def test_probe_fallback_accepts_service_asset_status_only(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="missing.example.cn",
        url="http://missing.example.cn/",
        normalized_url="http://missing.example.cn/",
        http_status=404,
        evidence={"source": "service_asset", "service_asset_id": 1},
    )
    session.add(entry)
    session.commit()

    saved = UrlDiscoveryService(session, config)._save_probe_fallback(entry.id, "timeout")
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.evidence["visual_analysis"]["analysis_method"] == "http_probe_fallback"
    assert refreshed.evidence["visual_analysis"]["confidence"] == 0.35


def test_probe_fallback_accepts_passive_service_asset_without_status(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(
        scan_task_id=1,
        host="8.8.8.8",
        url="http://8.8.8.8:9980/",
        normalized_url="http://8.8.8.8:9980/",
        title="工单系统",
        evidence={"source": "service_asset", "service_asset_id": 1},
    )
    session.add(entry)
    session.commit()

    saved = UrlDiscoveryService(session, config)._save_probe_fallback(entry.id, "timeout")
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.evidence["visual_analysis"]["website_title"] == "工单系统"


def test_probe_fallback_uses_service_asset_title_when_entry_title_missing(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service_asset = ServiceAsset(
        scan_task_id=1,
        target_ip="8.8.8.8",
        protocol="tcp",
        port=9080,
        asset_kind="web",
        product="WebSphere Application Server/6.1",
    )
    session.add(service_asset)
    session.commit()
    session.refresh(service_asset)
    entry = WebEntrypoint(
        scan_task_id=1,
        service_asset_id=service_asset.id,
        host="8.8.8.8",
        url="http://8.8.8.8:9080/",
        normalized_url="http://8.8.8.8:9080/",
        evidence={"source": "service_asset", "service_asset_id": service_asset.id},
    )
    session.add(entry)
    session.commit()

    saved = UrlDiscoveryService(session, config)._save_probe_fallback(entry.id, "timeout")
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.evidence["visual_analysis"]["website_title"] == "WebSphere Application Server/6.1"


def test_reuse_duplicate_visual_analysis_by_body_hash(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="a.example.cn",
            url="https://a.example.cn/",
            normalized_url="https://a.example.cn/",
            body_hash="same",
            evidence={"visual_analysis": {"system_name": "A"}},
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="b.example.cn",
            url="https://b.example.cn/",
            normalized_url="https://b.example.cn/",
            body_hash="same",
            evidence={"visual_analysis_error": "old timeout"},
        )
    )
    session.commit()

    changed = UrlDiscoveryService(session, config)._reuse_duplicate_visual_analysis(1)
    rows = {row.host: row for row in session.exec(select(WebEntrypoint)).all()}

    assert changed == 1
    assert rows["b.example.cn"].evidence["visual_analysis"]["system_name"] == "A"
    assert rows["b.example.cn"].evidence["visual_analysis"]["analysis_method"] == "duplicate_reuse"
    assert "visual_analysis_error" not in rows["b.example.cn"].evidence
