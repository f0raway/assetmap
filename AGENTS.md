# AGENTS.md — assetmap

Chinese-language cybersecurity asset-mapping CLI. Python 3.9+, Typer CLI, SQLModel/SQLite, Pydantic v2 config, httpx, openpyxl, python-docx. Orchestrate external tools (subfinder, dnsx, nmap), FOFA API, Playwright screenshots, and an OpenAI-compatible AI gateway into a resumable pipeline that produces Word/Excel deliverables.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,visual]"     # dev=pytest, visual=playwright
playwright install chromium         # required for url-discover stage
assetmap init                       # generates config.yaml + data/assetmap.db (idempotent, won't overwrite)
assetmap init --force               # overwrite config.yaml
assetmap env-check                  # verify external tool availability
assetmap ai-check                   # verify AI endpoint connectivity
```

`config.yaml` is gitignored. Copy from `config.example.yaml` or let `assetmap init` generate it. Requires real values for: `enscan.tycid`, `enscan.auth_token`, `fofa.email`, `fofa.api_key`, `ai.base_url`, `ai.api_key`.

## Commands

```bash
assetmap scan "公司名称"                          # one-shot: full pipeline with breakpoint resume
assetmap scan "公司名称" --refresh                # discard previous task, start fresh
assetmap scan "公司名称" --strict                 # block delivery on any WARN
assetmap scan "公司名称" --manual-file data/manual_assets.yaml  # import manual assets during scan
assetmap scan "公司名称" --no-manual-prompt       # skip manual asset prompt after discover
assetmap scan "公司名称" --manual-add             # enter TUI to add assets after discover

assetmap discover "公司名称"                      # stage 1 only: corporate asset collection
assetmap run <task_id>                            # resume from last incomplete stage
assetmap run <task_id> --from-stage subdomains    # jump to specific stage
assetmap run <task_id> --from-stage subdomains --rerun-dns     # force redo DNS
assetmap run <task_id> --from-stage port-scan --rerun-ports    # force redo port scan
assetmap run <task_id> --from-stage classify --rerun-classify  # force redo classification
assetmap run <task_id> --from-stage url-discover --retry-failed  # retry failed/downgraded pages
assetmap run <task_id> --from-stage url-discover --rerun-urls    # redo all URL visual analysis
assetmap run <task_id> --from-stage report --rerun-ai            # redo AI report analysis

assetmap report <task_id>                         # generate Word + Excel reports
assetmap quality-check <task_id>                  # PASS / WARN / FAIL gate
assetmap review-workorder <task_id> --output data/review_workorder.task_<task_id>.yaml --force
assetmap import-review <task_id> --file data/review_workorder.task_<task_id>.yaml
assetmap improve <task_id>                        # generate improvement plan
assetmap improve <task_id> --execute              # auto-execute improvement actions
assetmap deliver <task_id>                        # package delivery zip
assetmap verify-package deliveries/task_<task_id>_<target>.zip

assetmap status <task_id>                         # pipeline progress
assetmap show <task_id>                           # summary view
assetmap export <task_id> --format json
assetmap import-assets <task_id> --file data/manual_assets.yaml
assetmap asset-template --output data/manual_assets.yaml
assetmap asset-gap-template <task_id> --priority high-medium --include-partial --force --output data/gaps.yaml

# 新增命令
assetmap configure                                # TUI 配置向导：交互式配置 API 密钥
assetmap install-tools                            # 安装外部工具：subfinder, dnsx, nmap
assetmap install-tools subfinder                  # 只安装特定工具
assetmap env-check                                # 检查环境依赖（改进后的友好输出）
```

## Pipeline Stages (in order)

1. `discover` — Corporate equity, ICP filings, domains, apps, mini-programs, WeChat accounts, emails
2. Manual asset import
3. `subdomains` — subfinder (passive) + dnsx (active wordlist discovery and DNS resolution) → AI judges real server IPs
4. `port-scan` — nmap (active) + FOFA (passive), merged/deduped
5. `classify` — Service identification → Web URL entry generation
6. `url-discover` — Playwright screenshots → multimodal AI recognition
7. `report` — 4-chunk AI analysis (DNS, ports, Web, overall) → Word + 2 Excel files
8. `quality-check` → `deliver`

## Architecture

```
assetmap/
├── cli/                    # Typer CLI commands (split by domain)
│   ├── __init__.py         # Main app entry point, registers all commands
│   ├── common.py           # Shared utilities and helpers
│   ├── config.py           # init, configure, env-check, ai-check, install-tools
│   ├── pipeline.py         # scan, discover, run, subdomains, port-scan, classify, url-discover
│   ├── report.py           # report, deliver, quality-check, package-report, verify-package
│   ├── assets.py           # import-assets, asset-template, asset-gap-template, dedupe-assets, export
│   ├── review.py           # review-workorder, import-review, improvement-plan, improve
│   └── show.py             # show, status
├── config.py               # Pydantic AppConfig, load_config(), write_sample_config()
├── db.py                   # SQLModel engine + session
├── models.py               # DB models: Company, ScanTask, InternetAsset, CompanyEdge, etc.
├── utils.py
├── collectors/
│   └── tyc_invest_crawler.py   # ENScan/TYC corporate data collector (configurable via enscan.script)
└── services/               # Grouped by business capability
    ├── acquisition/        # enterprise discovery and manual asset import
    ├── mapping/            # subdomains, DNS, FOFA and port discovery
    ├── identification/     # service, Web and AI identification
    ├── delivery/           # export, report, quality and package
    ├── operations/         # status, review, improvement and maintenance
    └── runtime/            # config wizard, environment and external tools
```

## Key Conventions

- **Breakpoint resume is default.** Same company name → reuses last task. Use `--refresh` to restart. `run` without `--rerun-*` only processes incomplete/stale stages.
- **External tools** live in `tools/{subfinder,dnsx,nmap}/`. `runtime/tool_resolver.py` finds binaries. Commands are templated in `config.yaml` with `{binary}`, `{domain}`, `{output}`, `{target}`, `{wordlist}`, `{xml_output}`, `{normal_output}`, `{targets_file}`, `{ports}` placeholders.
- **AI client** (`identification/ai_client.py`) is OpenAI-compatible. Config: `ai.base_url`, `ai.api_key`, `ai.api_key_header` (default `api-key`), `ai.model`. Used for DNS IP judgment, visual screenshot analysis, and report generation.
- **Data directory** (`data/`) is mostly gitignored. Tracked: `data/wordlists/`, `data/manual_assets.example.yaml`. Generated: `data/assetmap.db`, `data/enscan/`, `data/subdomains/`, `data/nmap/`, `data/classify/`, `data/screenshots/`, `data/report/`.
- **Report output** goes to `reports/task_<task_id>_<target>/`. Delivery zips go to `deliveries/`.
- **Quality gate**: PASS = deliverable; WARN = deliverable with gaps (review workorder + improvement plan attached); FAIL = must fix before delivery. `--strict` turns WARN into a hard stop.
- **All user-facing output and docs are in Chinese.** Code comments and variable names are in English.

## Testing

```bash
pytest                    # run all tests in tests/
pytest tests/test_config.py              # single file
pytest tests/test_config.py::test_name   # single test
```

No special fixtures or services required for unit tests. Integration tests that call external tools/APIs may be skipped without config.

## Things an Agent Might Get Wrong

- Do NOT commit `config.yaml`, `data/assetmap.db`, `deliveries/`, `exports/`, or `data/` results.
- Do NOT assume `config.yaml` exists — run `assetmap init` first.
- Do NOT run `pip install -e .` without extras if visual features are needed — use `.[dev,visual]`.
- Do NOT invent pipeline stage names — they are exactly: `subdomains`, `port-scan`, `classify`, `url-discover`, `report` (see `PIPELINE_STAGES` in `cli/common.py`).
- Do NOT skip `--rerun-*` flags when you want to redo a stage — `run` alone is incremental.
- Do NOT treat WARN from quality-check as a failure — it's expected for partial coverage.
- Wordlist path is configured at `tools.wordlist` (default `data/wordlists/Subdomain.txt`).
