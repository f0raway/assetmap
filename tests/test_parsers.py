from assetmap.services.mapping.nmap_scan import extract_ai_marked_service_ips
from assetmap.config import FofaConfig
from assetmap.services.mapping.fofa import FofaClient
from assetmap.utils import extract_percent


def test_extract_percent():
    assert extract_percent("60%") == 0.6
    assert extract_percent(0.51) == 0.51
    assert extract_percent("40") == 0.4


def test_extract_ai_marked_service_ips_only_uses_real_public_segment():
    text = """
    ### 一、真实公网服务 IP
    - 8.8.8.8: DNS service
    - 203.0.113.10: documentation address, should be ignored
    - 198.19.1.1: benchmark range, should be ignored
    ### 二、CDN 接入识别
    - 1.1.1.1: CDN candidate outside target section
    """
    assert extract_ai_marked_service_ips(text) == ["8.8.8.8"]


def test_extract_ai_marked_service_ips_prefers_machine_block():
    text = """
    NMAP_TARGET_IPS
    - 8.8.4.4 | high | direct A record
    END_NMAP_TARGET_IPS

    ### 一、真实公网服务 IP
    - 1.1.1.1: old fallback text should not be used
    """
    assert extract_ai_marked_service_ips(text) == ["8.8.4.4"]


def test_parse_fofa_results():
    client = FofaClient(FofaConfig())
    payload = {
        "error": False,
        "results": [
            ["https://example.com", "8.8.8.8", "443", "https", "Example", "nginx"],
            ["ssh://8.8.8.8", "8.8.8.8", "22", "ssh", "", "OpenSSH"],
        ],
    }

    rows = client._parse_results(payload, ["host", "ip", "port", "protocol", "title", "server"], "8.8.8.8")

    assert [(row.ip, row.port, row.protocol, row.host) for row in rows] == [
        ("8.8.8.8", 443, "https", "https://example.com"),
        ("8.8.8.8", 22, "ssh", "ssh://8.8.8.8"),
    ]
