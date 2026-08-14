#!/usr/bin/env python3
"""Build assetmap's compact, high-coverage dnsx wordlist.

The input order is treated as its source priority.  We keep the first 300,000
unique RFC-style host labels, retain valid two- and three-label prefixes such
as ``api.dev``, and add a small set of high-value labels that commonly expose
management, CI/CD, observability, cloud and Chinese business systems.  This
deliberately excludes malformed records, underscore service records,
duplicates and SEO-style long-tail noise.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


MAX_ENTRIES = 300_000
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# These terms are retained even if their first occurrence is beyond the source
# priority cutoff.  Keep this list short: it is a coverage safety net, not a
# second large wordlist.
HIGH_VALUE_LABELS = (
    "iot", "k8s", "kubernetes", "grafana", "kibana", "prometheus",
    "elasticsearch", "rabbitmq", "redis", "mongodb", "postgres",
    "jenkins", "gitlab", "gitea", "harbor", "nexus", "consul", "vault",
    "rancher", "sonarqube", "sentry", "zookeeper", "kafka", "minio",
    "openvpn", "wireguard", "uat", "sit", "fat", "pre", "prod",
    "ceshi", "guanli", "xitong", "yewu", "shuju", "neibu", "wangguan",
    # Common modern Web, API, authentication and platform entrypoints that
    # were absent from the legacy source or appeared too far into its tail.
    "api0", "api-gateway", "gateway-api", "graphql", "grpc", "websocket",
    "ingress", "reverse-proxy", "admin-api", "admin-console", "adminportal",
    "keycloak", "oauth2", "oidc", "auth-api", "healthz", "tracing",
    "builds", "repositories", "artifacts", "kube", "kubectl", "argocd",
    "redis-admin", "etcd", "nacos", "seata", "jumpserver", "miniapp",
)


def normalize_label(value: str) -> str | None:
    label = value.strip().lower()
    return label if LABEL.fullmatch(label) else None


def normalize_prefix(value: str) -> str | None:
    prefix = value.strip().lower().rstrip(".")
    labels = prefix.split(".")
    if 1 <= len(labels) <= 3 and all(LABEL.fullmatch(label) for label in labels):
        return ".".join(labels)
    return None


def compact_labels(lines: list[str], max_entries: int = MAX_ENTRIES) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    nested: list[str] = []
    for line in lines:
        prefix = normalize_prefix(line)
        if not prefix:
            continue
        if "." in prefix:
            if prefix not in seen:
                seen.add(prefix)
                nested.append(prefix)
            continue
        if len(selected) < max_entries and prefix not in seen:
            seen.add(prefix)
            selected.append(prefix)
    selected.extend(nested)
    for label in HIGH_VALUE_LABELS:
        if label not in seen:
            seen.add(label)
            selected.append(label)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="构建精简高覆盖 dnsx 子域名字典。")
    parser.add_argument("input", type=Path, help="原始字典文件")
    parser.add_argument("output", type=Path, help="精简字典输出文件")
    parser.add_argument("--max-entries", type=int, default=MAX_ENTRIES, help="保留的原始优先级候选数")
    args = parser.parse_args()
    if args.max_entries <= 0:
        parser.error("--max-entries 必须大于 0")
    lines = args.input.read_text(encoding="utf-8", errors="ignore").splitlines()
    compact = compact_labels(lines, args.max_entries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(compact) + "\n", encoding="utf-8")
    print(f"input={len(lines):,} compact={len(compact):,} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
