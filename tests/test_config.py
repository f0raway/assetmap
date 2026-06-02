from pathlib import Path

from assetmap.config import load_config, write_sample_config


def test_write_and_load_sample_config(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    config = load_config(config_path)
    assert config.org.control_threshold == 0.5
    assert config.enscan.script.endswith("tyc_invest_crawler.py")
    assert config.enscan.script.startswith("assetmap/collectors")
    assert config.enscan.tycid == "YOUR_TYCID"
    assert config.enscan.auth_token == "YOUR_TYC_AUTH_TOKEN"
    assert config.enscan.request_delay_seconds == 1.0
    assert config.enscan.request_timeout_seconds == 20
    assert config.enscan.asset_workers == 1
    assert config.enscan.verbose is False
    assert config.tools.subdomain_tools_enabled == ["subfinder", "ksubdomain"]
    assert config.tools.subdomain_tool_timeout_seconds == 300
    assert "ksubdomain" in config.tools.ksubdomain_command or "enum" in config.tools.ksubdomain_command
    assert config.tools.wordlist.endswith("Subdomain.txt")
    assert "--top-ports 100" in config.tools.nmap_command
    assert "{target}" in config.tools.nmap_command
    assert "{xml_output}" in config.tools.nmap_command
    assert config.tools.nmap_mode == "batch"
    assert "-iL {targets_file}" in config.tools.nmap_batch_command
    assert config.tools.nmap_max_workers == 3
    assert config.tools.nmap_timeout_seconds == 600
    assert "-sV" in config.tools.nmap_service_detect_command
    assert "{ports}" in config.tools.nmap_service_detect_command
    assert config.port_scan.sources_enabled == ["nmap"]
    assert config.port_scan.target_sources_enabled == ["ai", "manual", "dns_public"]
    assert config.fofa.base_url == "https://fofa.info"
    assert config.fofa.email == "YOUR_FOFA_EMAIL"
    assert config.fofa.api_key == "YOUR_FOFA_API_KEY"
    assert "ip" in config.fofa.fields
    assert config.dns.max_workers == 20
    assert config.ai.enabled is False
    assert config.ai.max_dns_records == 2000
    assert config.ai.max_prompt_chars == 60000
    assert config.ai.base_url == "https://token-plan-cn.xiaomimimo.com/v1"
    assert config.ai.api_key == "YOUR_MIMO_API_KEY"
    assert config.ai.api_key_header == "api-key"
    assert config.ai.model == "mimo-v2.5"
    assert config.ai.max_completion_tokens == 4096
    assert "Chrome" in config.web_probe.user_agent
    assert config.web_probe.max_workers == 20
    assert config.url_discovery.browser_channel == "chrome"
    assert config.url_discovery.timeout_seconds == 15
    assert config.url_discovery.page_hard_timeout_seconds == 60
    assert config.url_discovery.ai_timeout_seconds == 90
    assert config.url_discovery.visual_max_pages == 50


def test_write_sample_config_can_keep_existing_file(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("database:\n  url: sqlite:///custom.db\n", encoding="utf-8")

    write_sample_config(config_path, overwrite=False)

    assert "custom.db" in config_path.read_text(encoding="utf-8")
