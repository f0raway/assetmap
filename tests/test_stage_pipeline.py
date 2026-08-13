from types import SimpleNamespace

from assetmap.config import AppConfig
from assetmap.stages import pipeline


def _completed_statuses():
    return {
        "discover": "completed",
        "subdomains": "completed",
        "port-scan": "completed",
        "classify": "completed",
        "url-discover": "completed",
        "report": "completed",
    }


def test_target_pipeline_calls_public_stage_modules_in_order(monkeypatch):
    calls: list[str] = []

    def record(name, result=None):
        def fake(*args, **kwargs):
            calls.append(name)
            return result

        return fake

    monkeypatch.setattr(pipeline.enterprise_discovery, "run", record("enterprise-discovery", SimpleNamespace(task_id=49)))
    monkeypatch.setattr(pipeline.domain_mapping, "run", record("domain-mapping"))
    monkeypatch.setattr(pipeline.port_discovery, "run", record("port-discovery"))
    monkeypatch.setattr(pipeline.service_identification, "run", record("service-identification"))
    monkeypatch.setattr(pipeline.web_identification, "run", record("web-identification"))
    monkeypatch.setattr(pipeline.report_generation, "run", record("report-generation"))
    monkeypatch.setattr(pipeline, "_stage_statuses", lambda *args: {name: "pending" for name in _completed_statuses()})

    result = pipeline.run(AppConfig(), target="测试企业", progress=lambda _: None)

    assert result.task_id == 49
    assert result.executed == (
        "enterprise-discovery",
        "domain-mapping",
        "port-discovery",
        "service-identification",
        "web-identification",
        "report-generation",
    )
    assert calls == list(result.executed)


def test_completed_task_is_skipped_without_explicit_rerun(monkeypatch):
    calls: list[str] = []

    def unexpected(*args, **kwargs):
        calls.append("called")

    monkeypatch.setattr(pipeline.domain_mapping, "run", unexpected)
    monkeypatch.setattr(pipeline.port_discovery, "run", unexpected)
    monkeypatch.setattr(pipeline.service_identification, "run", unexpected)
    monkeypatch.setattr(pipeline.web_identification, "run", unexpected)
    monkeypatch.setattr(pipeline.report_generation, "run", unexpected)
    monkeypatch.setattr(pipeline, "_stage_statuses", lambda *args: _completed_statuses())

    result = pipeline.run(
        AppConfig(),
        task_id=49,
        from_stage="subdomains",
        progress=lambda _: None,
    )

    assert not calls
    assert result.executed == ()
    assert result.skipped == (
        "domain-mapping",
        "port-discovery",
        "service-identification",
        "web-identification",
        "report-generation",
    )


def test_domain_gap_resumes_and_refreshes_later_stages(monkeypatch):
    calls: list[str] = []

    def record(name):
        def fake(*args, **kwargs):
            calls.append(name)

        return fake

    statuses = _completed_statuses()
    statuses["subdomains"] = "completed_with_gaps"
    monkeypatch.setattr(pipeline, "_stage_statuses", lambda *args: statuses)
    monkeypatch.setattr(pipeline.domain_mapping, "run", record("domain-mapping"))
    monkeypatch.setattr(pipeline.port_discovery, "run", record("port-discovery"))
    monkeypatch.setattr(pipeline.service_identification, "run", record("service-identification"))
    monkeypatch.setattr(pipeline.web_identification, "run", record("web-identification"))
    monkeypatch.setattr(pipeline.report_generation, "run", record("report-generation"))

    result = pipeline.run(AppConfig(), task_id=49, from_stage="subdomains", progress=lambda _: None)

    assert calls == [
        "domain-mapping",
        "port-discovery",
        "service-identification",
        "web-identification",
        "report-generation",
    ]
    assert result.executed == tuple(calls)
