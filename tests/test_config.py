from pathlib import Path

from assetmap.config import load_config, write_sample_config


def test_write_and_load_sample_config(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    write_sample_config(config_path)
    content = config_path.read_text(encoding="utf-8")
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
    assert config.tools.subdomain_tools_enabled == ["subfinder", "dnsx"]
    assert config.tools.subdomain_tool_timeout_seconds == 300
    assert config.tools.subdomain_tool_max_output_lines == 10000
    assert "-wt 5" in config.tools.dnsx_command
    assert "-auto-wildcard" not in config.tools.dnsx_command
    assert "-resp" not in config.tools.dnsx_command
    assert "-timeout" not in config.tools.dnsx_command
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
    assert config.ai.base_url == "https://api.openai.com/v1"
    assert config.ai.api_key == "YOUR_OPENAI_API_KEY"
    assert config.ai.api_key_header == "Authorization"
    assert config.ai.model == "gpt-4o"
    assert config.ai.max_completion_tokens == 4096
    assert "max_dns_records" not in content
    assert "max_prompt_chars" not in content
    assert "max_completion_tokens" not in content
    assert "Chrome" in config.web_probe.user_agent
    assert config.web_probe.max_workers == 20
    assert config.url_discovery.browser_channel == ""
    assert config.url_discovery.timeout_seconds == 15
    assert config.url_discovery.page_hard_timeout_seconds == 60
    assert config.url_discovery.ai_timeout_seconds == 90
    assert config.url_discovery.visual_max_pages == 50


def test_write_sample_config_can_keep_existing_file(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("database:\n  url: sqlite:///custom.db\n", encoding="utf-8")

    write_sample_config(config_path, overwrite=False)

    assert "custom.db" in config_path.read_text(encoding="utf-8")


def test_config_strips_secrets_and_clamps_risky_limits(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "enscan:",
                "  tycid: '  tycid-value  '",
                '  auth_token: "  token-value\\n  "',
                "fofa:",
                "  email: '  user@example.com  '",
                "  api_key: '  fofa-key  '",
                "dns:",
                "  lifetime_seconds: 1000",
                "  nameservers: [' 223.5.5.5 ', '']",
                "ai:",
                "  api_key: '  ai-key  '",
                "  max_completion_tokens: 100000",
            ]
        ),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.enscan.tycid == "tycid-value"
    assert config.enscan.auth_token == "token-value"
    assert config.fofa.email == "user@example.com"
    assert config.fofa.api_key == "fofa-key"
    assert config.dns.lifetime_seconds == 60.0
    assert config.dns.nameservers == ["223.5.5.5"]
    assert config.ai.api_key == "ai-key"
    assert config.ai.max_completion_tokens == 8192
