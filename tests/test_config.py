from pathlib import Path

from assetmap.config import load_config, resolve_config_path, write_sample_config


def test_write_and_load_sample_config(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    content = config_path.read_text(encoding="utf-8")
    config = load_config(config_path)
    assert config.enterprise_discovery.control_threshold == 0.47
    assert "# assetmap 深度测绘配置。" in content
    assert config.enterprise_discovery.tycid == "YOUR_TYCID"
    assert config.enterprise_discovery.auth_token == "YOUR_TYC_AUTH_TOKEN"
    assert config.enterprise_discovery.max_depth == 10
    assert "request_delay_seconds" not in content
    assert "asset_workers" not in content
    assert config.domain_mapping.subfinder_provider_config.endswith("provider-config.yaml")
    assert config.domain_mapping.dnsx_wordlist.endswith("Subdomain.txt")
    assert "-p-" in config.tools.nmap_command
    assert "{targets_file}" in config.tools.nmap_command
    assert "{xml_output}" in config.tools.nmap_command
    assert "-iL {targets_file}" in config.tools.nmap_command
    assert "-sV" in config.tools.nmap_command
    assert "--script-timeout 60s" in config.tools.nmap_command
    assert "host-timeout" not in config.tools.nmap_command
    assert "-json" in config.tools.httpx_command
    assert "{input_file}" in config.tools.httpx_command
    assert "-t 30" in config.tools.httpx_command
    assert "-rl 100" in config.tools.httpx_command
    assert "httpx_command" not in content
    assert config.fofa.email == "YOUR_FOFA_EMAIL"
    assert config.fofa.api_key == "YOUR_FOFA_API_KEY"
    assert not hasattr(config, "port_scan")
    assert not hasattr(config.tools, "nmap_timeout_seconds")
    assert not hasattr(config.fofa, "base_url")
    assert config.ai.enabled is True
    assert config.ai.max_dns_records == 5000
    assert config.ai.max_prompt_chars == 120000
    assert config.ai.base_url == "https://api.openai.com/v1"
    assert config.ai.api_key == "YOUR_OPENAI_API_KEY"
    assert config.ai.api_key_header == "Authorization"
    assert config.ai.model == "gpt-4o"
    assert config.ai.max_completion_tokens == 8192
    assert "max_dns_records" not in content
    assert "max_prompt_chars" not in content
    assert "max_completion_tokens" not in content
    assert "Chrome" in config.web_probe.user_agent
    assert not hasattr(config.web_probe, "max_body_bytes")
    assert not hasattr(config.web_probe, "max_workers")
    assert not hasattr(config.web_probe, "max_domains_per_ip")
    assert config.url_discovery.timeout_seconds == 15
    assert config.url_discovery.page_hard_timeout_seconds == 60
    assert config.url_discovery.ai_timeout_seconds == 240
    assert not hasattr(config.url_discovery, "visual_max_pages")
    assert "visual_max_pages" not in content


def test_write_sample_config_can_keep_existing_file(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("database:\n  url: sqlite:///custom.db\n", encoding="utf-8")

    write_sample_config(config_path, overwrite=False)

    assert "custom.db" in config_path.read_text(encoding="utf-8")


def test_default_config_resolves_to_project_root_when_called_in_package_dir(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    package_dir = project / "assetmap"
    package_dir.mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname = 'assetmap'\n", encoding="utf-8")
    (project / "config.yaml").write_text("database:\n  url: sqlite:///data/assetmap.db\n", encoding="utf-8")
    monkeypatch.chdir(package_dir)

    config = load_config()

    assert resolve_config_path() == project / "config.yaml"
    assert config.database_url == f"sqlite:///{project / 'data' / 'assetmap.db'}"


def test_legacy_nmap_batch_template_is_migrated(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "tools:\n"
        "  nmap_mode: batch\n"
        "  nmap_command: 'legacy-single {target}'\n"
        "  nmap_batch_command: 'legacy-batch -iL {targets_file}'\n",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.tools.nmap_command == "legacy-batch -iL {targets_file}"


def test_config_strips_secrets_and_clamps_risky_limits(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "enterprise_discovery:",
                "  tycid: '  tycid-value  '",
                '  auth_token: "  token-value\\n  "',
                "fofa:",
                "  email: '  user@example.com  '",
                "  api_key: '  fofa-key  '",
                "ai:",
                "  api_key: '  ai-key  '",
                "  max_completion_tokens: 100000",
            ]
        ),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.enterprise_discovery.tycid == "tycid-value"
    assert config.enterprise_discovery.auth_token == "token-value"
    assert config.fofa.email == "user@example.com"
    assert config.fofa.api_key == "fofa-key"
    assert config.ai.api_key == "ai-key"
    assert config.ai.max_completion_tokens == 8192


def test_legacy_enscan_and_org_configuration_is_migrated(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "org:\n"
        "  control_threshold: 0.55\n"
        "  max_depth: 7\n"
        "enscan:\n"
        "  tycid: legacy-tycid\n"
        "  auth_token: legacy-token\n",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.enterprise_discovery.tycid == "legacy-tycid"
    assert config.enterprise_discovery.auth_token == "legacy-token"
    assert config.enterprise_discovery.control_threshold == 0.55
    assert config.enterprise_discovery.max_depth == 7
