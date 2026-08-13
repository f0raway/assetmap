from pathlib import Path
import json

import httpx
from sqlmodel import select

from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import ServiceAsset, UrlDiscoveryTask, WebEntrypoint, WebProbeResult
from assetmap.services.identification.url_discovery import UrlDiscoveryService, _clean_ai_text, _looks_blank, _page_state_summary


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


def test_run_requires_service_identification_before_visual_stage(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    from pytest import raises

    with raises(ValueError, match="service-identification"):
        UrlDiscoveryService(session, config).run(1)

    task = session.exec(select(UrlDiscoveryTask).where(UrlDiscoveryTask.scan_task_id == 1)).one()
    assert task.status == "failed"


def test_web_identification_fails_when_playwright_is_missing(tmp_path: Path, monkeypatch):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ServiceAsset(scan_task_id=1, target_ip="8.8.8.8", port=80, asset_kind="web"))
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="portal.example.cn",
            url="https://portal.example.cn/",
            normalized_url="https://portal.example.cn/",
            http_status=200,
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="failed.example.cn",
            url="https://failed.example.cn/",
            normalized_url="https://failed.example.cn/",
            evidence={"visual_analysis_error": "old model failure", "visual_analysis_screenshot_path": "failed.png"},
        )
    )
    session.commit()
    service = UrlDiscoveryService(session, config)
    monkeypatch.setattr(
        service,
        "_require_playwright",
        lambda: (_ for _ in ()).throw(RuntimeError("Playwright is not installed")),
    )

    from pytest import raises

    with raises(RuntimeError, match="Playwright is not installed"):
        service.run(1)

    task = session.exec(select(UrlDiscoveryTask).where(UrlDiscoveryTask.scan_task_id == 1)).one()
    assert task.status == "failed"


def test_entrypoint_count_reports_deduplicated_database_total(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(WebEntrypoint(scan_task_id=1, host="a.example.cn", url="https://a.example.cn/", normalized_url="https://a.example.cn/"))
    session.add(WebEntrypoint(scan_task_id=1, host="b.example.cn", url="https://b.example.cn/", normalized_url="https://b.example.cn/"))
    session.commit()

    assert UrlDiscoveryService(session, config)._entrypoint_count(1) == 2


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


def test_rendered_html_ai_retries_when_json_is_truncated(tmp_path: Path, monkeypatch):
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
    )
    calls = []

    def fake_chat_completion(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            return {"choices": [{"finish_reason": "length", "message": {"content": '{"system_name": "截断'}}]}
        return {"choices": [{"finish_reason": "stop", "message": {"content": '{"system_name": "统一门户", "confidence": 0.9}'}}]}

    monkeypatch.setattr("assetmap.services.identification.url_discovery.chat_completion", fake_chat_completion)

    analysis = UrlDiscoveryService(session, config)._analyze_rendered_html_with_ai(
        entry,
        {"final_url": entry.url, "document_title": "统一门户", "visible_text": "统一登录", "rendered_html": "<html>统一登录</html>"},
    )

    assert analysis["system_name"] == "统一门户"
    assert analysis["retry_reason"] == "finish_reason=length"
    assert [call[1]["max_completion_tokens"] for call in calls] == [1200, 1600]


def test_rendered_html_prompt_is_text_only_and_bounded(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    entry = WebEntrypoint(host="portal.example.cn", url="https://portal.example.cn/", normalized_url="https://portal.example.cn/")

    messages = UrlDiscoveryService(session, config)._rendered_html_messages(
        entry,
        {"rendered_html": "x" * 100_000, "visible_text": "登录" * 30_000},
    )

    assert isinstance(messages[1]["content"], str)
    assert "image_url" not in messages[1]["content"]
    assert len(messages[1]["content"]) < 150_000


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


def test_normalize_url_skips_invalid_textual_port(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    assert UrlDiscoveryService(session, config)._normalize_url("https://portal.example.cn:not-a-port/") is None


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
                evidence={"visual_analysis": {"system_name": "OK", "rendered_html_path": "ok.html"}},
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
        assert audit["method_counts"] == {"failed": 1, "manual_or_legacy": 1}
        assert audit["rendered_html_count"] == 1
        assert len(audit["entries"]) == 2
        assert audit["failed_samples"][0]["url"] == "https://fail.example.cn/"
        assert refreshed.evidence["visual_analysis"]["analysis_method"] == "manual_or_legacy"
    finally:
        os.chdir(old_cwd)


def test_save_analysis_syncs_visual_summary_to_service_asset(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    service_asset = ServiceAsset(
        scan_task_id=1,
        target_ip="203.0.113.10",
        port=443,
        asset_kind="web",
        representative_url="https://portal.example.cn/",
    )
    session.add(service_asset)
    session.commit()
    entry = WebEntrypoint(
        scan_task_id=1,
        service_asset_id=service_asset.id,
        target_ip="203.0.113.10",
        port=443,
        host="portal.example.cn",
        url="https://portal.example.cn/",
        normalized_url="https://portal.example.cn/",
        http_status=200,
        title="统一门户",
    )
    session.add(entry)
    session.commit()
    html_path = tmp_path / "portal.html"
    html_path.write_text("<html>portal</html>", encoding="utf-8")

    UrlDiscoveryService(session, config)._save_analysis(
        entry.id,
        html_path,
        "https://portal.example.cn/login",
        {"system_name": "统一门户", "site_purpose": "业务登录入口", "confidence": 0.92},
    )
    refreshed = session.get(ServiceAsset, service_asset.id)

    assert refreshed.evidence["visual_analysis_count"] == 1
    assert refreshed.evidence["rendered_html_count"] == 1
    assert refreshed.evidence["visual_analysis"]["system_name"] == "统一门户"
    assert refreshed.evidence["visual_entrypoints"][0]["url"] == "https://portal.example.cn/"
    assert refreshed.app_name == "统一门户"


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
            "visual_analysis_rendered_html_path": "old.html",
        },
    )
    session.add(entry)
    session.commit()

    UrlDiscoveryService(session, config)._clear_stale_visual_errors(1)
    refreshed = session.get(WebEntrypoint, entry.id)

    assert refreshed.evidence == {"visual_analysis": {"system_name": "OK"}}


def test_pending_entrypoints_prioritizes_useful_pages(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
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

    assert [row.host for row in pending] == ["portal.example.cn", "login.example.cn", "bad.example.cn"]


def test_probe_fallback_saves_visual_analysis_when_rendered_html_fails(tmp_path: Path):
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


def test_ai_fallback_keeps_rendered_html_and_probe_title(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    html_path = tmp_path / "portal.html"
    html_path.write_text("<html>portal</html>", encoding="utf-8")
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
        html_path=html_path,
        final_url="https://portal.example.cn/login",
    )
    refreshed = session.get(WebEntrypoint, entry.id)

    assert saved is True
    assert refreshed.final_url == "https://portal.example.cn/login"
    visual = refreshed.evidence["visual_analysis"]
    assert visual["analysis_method"] == "http_probe_fallback"
    assert visual["page_type"] == "ai_analysis_fallback"
    assert visual["rendered_html_path"] == str(html_path)
    assert visual["ai_error"] == "AI HTTP 404 Not Found"
    assert "visual_analysis_error" not in refreshed.evidence


def test_rendered_html_candidates_correct_plain_http_on_https_port(tmp_path: Path):
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

    candidates = UrlDiscoveryService(session, config)._rendered_html_candidate_urls(entry)

    assert candidates[0] == "https://portal.example.cn/login"
    assert "http://portal.example.cn:443/login" in candidates


def test_rendered_html_candidates_preserve_non_https_hint_url(tmp_path: Path):
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

    candidates = UrlDiscoveryService(session, config)._rendered_html_candidate_urls(entry)

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
            evidence={"visual_analysis": {"system_name": "A", "analysis_method": "rendered_html_ai"}},
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


def test_legacy_screenshot_results_are_migrated_but_manual_results_are_preserved(tmp_path: Path):
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="old.example.cn",
            url="https://old.example.cn/",
            normalized_url="https://old.example.cn/",
            evidence={"visual_analysis": {"analysis_method": "screenshot_ai", "screenshot_path": "old.png"}},
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="manual.example.cn",
            url="https://manual.example.cn/",
            normalized_url="https://manual.example.cn/",
            evidence={"visual_analysis": {"system_name": "人工确认系统"}},
        )
    )
    session.add(
        WebEntrypoint(
            scan_task_id=1,
            host="failed.example.cn",
            url="https://failed.example.cn/",
            normalized_url="https://failed.example.cn/",
            evidence={"visual_analysis_error": "old model failure", "visual_analysis_screenshot_path": "failed.png"},
        )
    )
    session.commit()

    changed = UrlDiscoveryService(session, config)._invalidate_legacy_visual_analysis(1)
    rows = {row.host: row for row in session.exec(select(WebEntrypoint)).all()}

    assert changed == 2
    assert "visual_analysis" not in rows["old.example.cn"].evidence
    assert rows["old.example.cn"].evidence["legacy_visual_analysis"]["analysis_method"] == "screenshot_ai"
    assert "visual_analysis_error" not in rows["failed.example.cn"].evidence
    assert rows["failed.example.cn"].evidence["legacy_visual_analysis"]["analysis_method"] == "screenshot_error"
    assert rows["manual.example.cn"].evidence["visual_analysis"]["system_name"] == "人工确认系统"


def test_same_run_body_hash_reuse_skips_duplicate_browser_and_ai_work(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ServiceAsset(scan_task_id=1, target_ip="203.0.113.10", port=443, asset_kind="web"))
    for host in ("a.example.cn", "b.example.cn"):
        session.add(
            WebEntrypoint(
                scan_task_id=1,
                host=host,
                url=f"https://{host}/",
                normalized_url=f"https://{host}/",
                body_hash="same-httpx-body",
                http_status=200,
                title="统一门户",
            )
        )
    session.commit()
    service = UrlDiscoveryService(session, config)
    capture_calls = []
    ai_calls = []

    class FakeBrowser:
        def close(self):
            return None

    def fake_capture(entry, output_dir, *, browser=None):
        capture_calls.append(entry.host)
        path = output_dir / f"{entry.host}.html"
        path.write_text("<html>统一门户</html>", encoding="utf-8")
        return path, "https://portal.example.cn/", {"final_url": "https://portal.example.cn/", "visible_text": "统一门户", "rendered_html": "<html>统一门户</html>"}

    def fake_ai(*args, **kwargs):
        ai_calls.append(1)
        return {"choices": [{"finish_reason": "stop", "message": {"content": '{"system_name":"统一门户","confidence":0.9}'}}]}

    monkeypatch.setattr(service, "_require_playwright", lambda: None)
    monkeypatch.setattr(service, "_new_rendered_html_session", lambda: FakeBrowser())
    monkeypatch.setattr(service, "_capture_rendered_html", fake_capture)
    monkeypatch.setattr("assetmap.services.identification.url_discovery.chat_completion", fake_ai)

    service.run(1)
    rows = {row.host: row for row in session.exec(select(WebEntrypoint)).all()}

    assert capture_calls == ["a.example.cn"]
    assert len(ai_calls) == 1
    assert rows["b.example.cn"].evidence["visual_analysis"]["analysis_method"] == "duplicate_reuse"


def test_same_rendered_evidence_reuses_ai_but_keeps_each_html_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'assetmap.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)
    session.add(ServiceAsset(scan_task_id=1, target_ip="203.0.113.10", port=443, asset_kind="web"))
    for host, body_hash in (("a.example.cn", "a"), ("b.example.cn", "b")):
        session.add(
            WebEntrypoint(
                scan_task_id=1,
                host=host,
                url=f"https://{host}/",
                normalized_url=f"https://{host}/",
                body_hash=body_hash,
                http_status=200,
                title="统一门户",
            )
        )
    session.commit()
    service = UrlDiscoveryService(session, config)
    capture_calls = []
    ai_calls = []

    class FakeBrowser:
        def close(self):
            return None

    def fake_capture(entry, output_dir, *, browser=None):
        capture_calls.append(entry.host)
        path = output_dir / f"{entry.host}.html"
        path.write_text("<html>统一门户</html>", encoding="utf-8")
        return path, "https://portal.example.cn/", {"final_url": "https://portal.example.cn/", "visible_text": "统一门户", "rendered_html": "<html>统一门户</html>"}

    def fake_ai(*args, **kwargs):
        ai_calls.append(1)
        return {"choices": [{"finish_reason": "stop", "message": {"content": '{"system_name":"统一门户","confidence":0.9}'}}]}

    monkeypatch.setattr(service, "_require_playwright", lambda: None)
    monkeypatch.setattr(service, "_new_rendered_html_session", lambda: FakeBrowser())
    monkeypatch.setattr(service, "_capture_rendered_html", fake_capture)
    monkeypatch.setattr("assetmap.services.identification.url_discovery.chat_completion", fake_ai)

    service.run(1)
    rows = {row.host: row for row in session.exec(select(WebEntrypoint)).all()}

    assert capture_calls == ["a.example.cn", "b.example.cn"]
    assert len(ai_calls) == 1
    assert rows["b.example.cn"].evidence["visual_analysis"]["analysis_method"] == "duplicate_reuse"
    assert rows["b.example.cn"].evidence["visual_analysis"]["rendered_html_path"].endswith("b.example.cn.html")


def test_rendered_html_capture_uses_a_browser_session_and_closes_an_owned_session(tmp_path: Path, monkeypatch):
    class FakeBrowser:
        closed = False
        received = None

        def capture(self, **kwargs):
            self.received = kwargs
            return "https://example.cn/", {"rendered_html": "<html>ok</html>", "visible_text": "ok"}

        def close(self):
            self.closed = True

    browser = FakeBrowser()
    service = UrlDiscoveryService(None, AppConfig())  # type: ignore[arg-type]
    monkeypatch.setattr(service, "_new_rendered_html_session", lambda: browser)
    entry = WebEntrypoint(
        host="example.cn",
        url="https://example.cn/",
        normalized_url="https://example.cn/",
    )

    html_path, final_url, rendered = service._capture_rendered_html(entry, tmp_path)

    assert html_path == tmp_path / "https_example.cn_example.cn.html"
    assert html_path.read_text(encoding="utf-8") == "<html>ok</html>"
    assert final_url == "https://example.cn/"
    assert rendered["visible_text"] == "ok"
    assert browser.closed is True
    assert browser.received["urls"] == ["https://example.cn/"]
