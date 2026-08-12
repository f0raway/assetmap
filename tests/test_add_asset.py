import typer
from sqlmodel import select

from assetmap.cli.assets import register
from assetmap.cli.pipeline import _prompt_manual_asset_import
from assetmap.config import AppConfig, DatabaseConfig
from assetmap.db import create_db_and_engine, get_session
from assetmap.models import Company, DnsRecord, InternetAsset, ScanTask
from assetmap.services.acquisition.manual_asset_wizard import ManualAssetWizardService


def test_add_asset_command_registered():
    app = typer.Typer()
    register(app)
    names = [cmd.name for cmd in app.registered_commands]
    assert "add-asset" in names


def test_wizard_adds_domain_through_import_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'test.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    task = ScanTask(target="测试公司", status="completed")
    company = Company(name="测试公司", normalized_name="测试公司")
    session.add(task)
    session.add(company)
    session.commit()
    session.refresh(task)

    # 直接调用 wizard._add_asset 绕过 questionary mock
    wizard = ManualAssetWizardService(session)
    wizard._add_asset(task.id, "domain", "test-domain.cn", "测试公司", {})

    assets = session.exec(
        select(InternetAsset).where(InternetAsset.asset_type == "icp_domain")
    ).all()
    assert len(assets) == 1
    assert assets[0].normalized_identifier == "test-domain.cn"


def test_wizard_adds_batch_ips_and_named_assets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'test.db'}"))
    engine = create_db_and_engine(config.database.url)
    session = get_session(engine)

    task = ScanTask(target="测试公司", status="completed")
    company = Company(name="测试公司", normalized_name="测试公司")
    session.add(task)
    session.add(company)
    session.commit()
    session.refresh(task)

    wizard = ManualAssetWizardService(session)
    ip_count = wizard._add_assets(task.id, "ip", ["8.8.8.8", "1.1.1.1"], "测试公司")
    app_count = wizard._add_assets(
        task.id,
        "app",
        [
            {"name": "测试 App", "package": "cn.example.test"},
            {"name": "测试办公"},
        ],
        "测试公司",
    )
    social_count = wizard._add_assets(
        task.id,
        "wechat_official_account",
        [{"name": "测试公众号"}, {"name": "测试安全中心", "account": "test-sec"}],
        "测试公司",
    )
    email_count = wizard._add_assets(task.id, "email", ["SECURITY@Example.cn"], "测试公司")

    assets = session.exec(select(InternetAsset)).all()
    by_type = {}
    for asset in assets:
        by_type.setdefault(asset.asset_type, set()).add(asset.normalized_identifier)

    assert ip_count == 2
    assert app_count == 2
    assert social_count == 2
    assert email_count == 1
    assert by_type["ip"] == {"8.8.8.8", "1.1.1.1"}
    assert by_type["app"] == {"cn.example.test", "测试办公"}
    assert by_type["wechat_official_account"] == {"测试公众号", "test-sec"}
    assert by_type["email"] == {"security@example.cn"}
    assert {row.value for row in session.exec(select(DnsRecord)).all()} == {"8.8.8.8", "1.1.1.1"}


def test_wizard_parses_batch_values():
    wizard = ManualAssetWizardService(object())  # type: ignore[arg-type]

    assert wizard._parse_values("a.example.cn，b.example.cn; c.example.cn\na.example.cn") == [
        "a.example.cn",
        "b.example.cn",
        "c.example.cn",
    ]


def test_scan_manual_add_enters_wizard(monkeypatch):
    calls = []

    class FakeWizard:
        def __init__(self, session, progress=None):
            calls.append("init")

        def run(self, task_id):
            calls.append(task_id)
            return True

    monkeypatch.setattr("assetmap.services.acquisition.manual_asset_wizard.ManualAssetWizardService", FakeWizard)

    changed = _prompt_manual_asset_import(
        object(),
        AppConfig(),
        49,
        company_count=1,
        asset_count=2,
        force_add=True,
        progress=lambda message: None,
    )

    assert changed is True
    assert calls == ["init", 49]
