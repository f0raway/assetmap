from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanTask(SQLModel, table=True):
    __tablename__ = "scan_tasks"

    id: Optional[int] = Field(default=None, primary_key=True)
    target: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)


class Company(SQLModel, table=True):
    __tablename__ = "companies"
    __table_args__ = (
        UniqueConstraint("uscc"),
        UniqueConstraint("normalized_name"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    normalized_name: str = Field(index=True)
    uscc: Optional[str] = Field(default=None, index=True)
    registration_status: Optional[str] = Field(default=None)
    legal_representative: Optional[str] = Field(default=None)
    area: Optional[str] = Field(default=None)
    industry: Optional[str] = Field(default=None)
    raw_payload: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=utcnow, nullable=False)


class CompanyEdge(SQLModel, table=True):
    __tablename__ = "company_edges"
    __table_args__ = (
        UniqueConstraint("task_id", "parent_company_id", "child_company_id"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    parent_company_id: int = Field(index=True, foreign_key="companies.id")
    child_company_id: int = Field(index=True, foreign_key="companies.id")
    direct_holding_ratio: float
    cumulative_holding_ratio: float
    depth: int = Field(index=True)
    path: str
    created_at: datetime = Field(default_factory=utcnow, nullable=False)


class InternetAsset(SQLModel, table=True):
    __tablename__ = "internet_assets"
    __table_args__ = (
        UniqueConstraint("asset_type", "normalized_identifier"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    asset_type: str = Field(index=True)
    normalized_identifier: str = Field(index=True)
    display_name: str
    raw_payload: dict = Field(sa_column=Column(JSON))
    first_seen_at: datetime = Field(default_factory=utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=utcnow, nullable=False)


class CompanyAssetLink(SQLModel, table=True):
    __tablename__ = "company_asset_links"
    __table_args__ = (
        UniqueConstraint("task_id", "company_id", "asset_id", "source_tool"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    company_id: int = Field(index=True, foreign_key="companies.id")
    asset_id: int = Field(index=True, foreign_key="internet_assets.id")
    source_tool: str
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)
    raw_payload: dict = Field(sa_column=Column(JSON))


class SourceRawRecord(SQLModel, table=True):
    __tablename__ = "source_raw_records"

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: Optional[int] = Field(default=None, index=True, foreign_key="scan_tasks.id")
    source: str = Field(index=True)
    action: str = Field(index=True)
    parameter_hash: str = Field(index=True)
    request_payload: dict = Field(sa_column=Column(JSON))
    response_json: dict = Field(sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow, nullable=False)


class SubdomainEnumerationTask(SQLModel, table=True):
    __tablename__ = "subdomain_enumeration_tasks"
    __table_args__ = (UniqueConstraint("scan_task_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    stage: str = Field(default="pending", index=True)


class SubdomainToolRun(SQLModel, table=True):
    __tablename__ = "subdomain_tool_runs"
    __table_args__ = (UniqueConstraint("scan_task_id", "root_domain", "tool_name"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    root_domain: str = Field(index=True)
    tool_name: str = Field(index=True)
    command: str
    output_path: str
    status: str = Field(default="pending", index=True)
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)
    exit_code: Optional[int] = Field(default=None)
    stdout: Optional[str] = Field(default=None)
    stderr: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)


class SubdomainRecord(SQLModel, table=True):
    __tablename__ = "subdomain_records"
    __table_args__ = (UniqueConstraint("scan_task_id", "fqdn"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    root_domain: str = Field(index=True)
    fqdn: str = Field(index=True)
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    first_seen_at: datetime = Field(default_factory=utcnow, nullable=False)
    last_seen_at: datetime = Field(default_factory=utcnow, nullable=False)


class DnsQueryStatus(SQLModel, table=True):
    __tablename__ = "dns_query_statuses"
    __table_args__ = (UniqueConstraint("scan_task_id", "fqdn", "record_type"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    fqdn: str = Field(index=True)
    root_domain: str = Field(index=True)
    record_type: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    error_message: Optional[str] = Field(default=None)
    queried_at: Optional[datetime] = Field(default=None)


class DnsRecord(SQLModel, table=True):
    __tablename__ = "dns_records"
    __table_args__ = (UniqueConstraint("scan_task_id", "fqdn", "record_type", "value"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    fqdn: str = Field(index=True)
    root_domain: str = Field(index=True)
    record_type: str = Field(index=True)
    value: str = Field(index=True)
    ttl: Optional[int] = Field(default=None)
    raw_payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)


class AiAnalysis(SQLModel, table=True):
    __tablename__ = "ai_analyses"
    __table_args__ = (UniqueConstraint("scan_task_id", "analysis_type"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    analysis_type: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    model: Optional[str] = Field(default=None)
    prompt_json: dict = Field(default_factory=dict, sa_column=Column(JSON))
    response_json: dict = Field(default_factory=dict, sa_column=Column(JSON))
    summary: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=utcnow, nullable=False)


class NmapScanTask(SQLModel, table=True):
    __tablename__ = "nmap_scan_tasks"
    __table_args__ = (UniqueConstraint("scan_task_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    targets: list[str] = Field(default_factory=list, sa_column=Column(JSON))


class NmapScanRun(SQLModel, table=True):
    __tablename__ = "nmap_scan_runs"
    __table_args__ = (UniqueConstraint("scan_task_id", "target_ip"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    target_ip: str = Field(index=True)
    command: str
    xml_output_path: str
    normal_output_path: str
    status: str = Field(default="pending", index=True)
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)
    exit_code: Optional[int] = Field(default=None)
    stdout: Optional[str] = Field(default=None)
    stderr: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)


class NmapPort(SQLModel, table=True):
    __tablename__ = "nmap_ports"
    __table_args__ = (UniqueConstraint("scan_task_id", "target_ip", "protocol", "port"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    target_ip: str = Field(index=True)
    protocol: str = Field(index=True)
    port: int = Field(index=True)
    state: str = Field(index=True)
    service: Optional[str] = Field(default=None)
    product: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    extra_info: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None)
    raw_payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)


class AssetClassificationTask(SQLModel, table=True):
    __tablename__ = "asset_classification_tasks"
    __table_args__ = (UniqueConstraint("scan_task_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    stage: str = Field(default="pending", index=True)


class WebProbeResult(SQLModel, table=True):
    __tablename__ = "web_probe_results"
    __table_args__ = (UniqueConstraint("scan_task_id", "target_ip", "port", "scheme", "host"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    target_ip: str = Field(index=True)
    port: int = Field(index=True)
    scheme: str = Field(index=True)
    host: str = Field(index=True)
    url: str
    status: str = Field(default="pending", index=True)
    http_status: Optional[int] = Field(default=None, index=True)
    final_url: Optional[str] = Field(default=None)
    title: Optional[str] = Field(default=None)
    server: Optional[str] = Field(default=None)
    powered_by: Optional[str] = Field(default=None)
    content_type: Optional[str] = Field(default=None)
    body_hash: Optional[str] = Field(default=None, index=True)
    body_length: Optional[int] = Field(default=None)
    tech_stack: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    error_message: Optional[str] = Field(default=None)
    raw_headers: dict = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)


class ServiceAsset(SQLModel, table=True):
    __tablename__ = "service_assets"
    __table_args__ = (UniqueConstraint("scan_task_id", "target_ip", "protocol", "port"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    target_ip: str = Field(index=True)
    protocol: str = Field(default="tcp", index=True)
    port: int = Field(index=True)
    asset_kind: str = Field(default="unknown", index=True)
    host_mode: str = Field(default="unknown", index=True)
    representative_url: Optional[str] = Field(default=None)
    domains: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    http_status: Optional[int] = Field(default=None)
    title: Optional[str] = Field(default=None)
    app_name: Optional[str] = Field(default=None)
    service: Optional[str] = Field(default=None)
    product: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    evidence: dict = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)


class UrlDiscoveryTask(SQLModel, table=True):
    __tablename__ = "url_discovery_tasks"
    __table_args__ = (UniqueConstraint("scan_task_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    stage: str = Field(default="pending", index=True)


class ReportGenerationTask(SQLModel, table=True):
    """Tracks report file generation separately from cached AI sections."""

    __tablename__ = "report_generation_tasks"
    __table_args__ = (UniqueConstraint("scan_task_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    report_path: Optional[str] = Field(default=None)
    asset_workbook_path: Optional[str] = Field(default=None)
    web_workbook_path: Optional[str] = Field(default=None)


class WebEntrypoint(SQLModel, table=True):
    __tablename__ = "web_entrypoints"
    __table_args__ = (UniqueConstraint("scan_task_id", "normalized_url"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_task_id: int = Field(index=True, foreign_key="scan_tasks.id")
    service_asset_id: Optional[int] = Field(default=None, index=True, foreign_key="service_assets.id")
    target_ip: Optional[str] = Field(default=None, index=True)
    port: Optional[int] = Field(default=None, index=True)
    host: str = Field(index=True)
    url: str
    normalized_url: str = Field(index=True)
    final_url: Optional[str] = Field(default=None)
    http_status: Optional[int] = Field(default=None, index=True)
    title: Optional[str] = Field(default=None)
    server: Optional[str] = Field(default=None)
    powered_by: Optional[str] = Field(default=None)
    content_type: Optional[str] = Field(default=None)
    body_hash: Optional[str] = Field(default=None, index=True)
    body_length: Optional[int] = Field(default=None)
    tech_stack: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    evidence: dict = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=utcnow, nullable=False)
