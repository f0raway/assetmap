from __future__ import annotations

import importlib.util
from pathlib import Path


def _module():
    path = Path(__file__).parents[1] / "scripts" / "compact_subdomain_wordlist.py"
    spec = importlib.util.spec_from_file_location("compact_subdomain_wordlist", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_compact_wordlist_keeps_ordered_valid_labels_and_high_value_fallbacks():
    module = _module()

    labels = module.compact_labels(
        ["WWW", "www", "api.dev", "_dmarc", "admin", "invalid value", "a-", "x"],
        max_entries=2,
    )

    assert labels[:2] == ["www", "admin"]
    assert "iot" in labels
    assert "graphql" in labels
    assert "api-gateway" in labels
    assert "api.dev" in labels
