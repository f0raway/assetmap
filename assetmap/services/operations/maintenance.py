from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, select

from assetmap.models import CompanyAssetLink, InternetAsset


def _norm(value: str | None) -> str:
    return "".join(str(value or "").split()).lower()


@dataclass
class DedupeResult:
    task_id: int
    removed_links: int


class MaintenanceService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def dedupe_asset_links(self, task_id: int) -> DedupeResult:
        links = self.session.exec(
            select(CompanyAssetLink)
            .where(CompanyAssetLink.task_id == task_id)
            .order_by(CompanyAssetLink.company_id, CompanyAssetLink.asset_id, CompanyAssetLink.id)
        ).all()
        asset_ids = [link.asset_id for link in links]
        assets = {
            asset.id: asset
            for asset in self.session.exec(select(InternetAsset).where(InternetAsset.id.in_(asset_ids))).all()
        }
        seen_exact: dict[tuple[int, int], CompanyAssetLink] = {}
        seen_semantic: dict[tuple[int, str, str], CompanyAssetLink] = {}
        removed = 0
        for link in links:
            asset = assets.get(link.asset_id)
            exact_key = (link.company_id, link.asset_id)
            semantic_key = self._semantic_key(link, asset)
            existing = seen_exact.get(exact_key) or (seen_semantic.get(semantic_key) if semantic_key else None)
            if not existing:
                seen_exact[exact_key] = link
                if semantic_key:
                    seen_semantic[semantic_key] = link
                continue
            existing_asset = assets.get(existing.asset_id)
            if self._asset_quality(asset) > self._asset_quality(existing_asset):
                self._merge_link(link, existing)
                seen_exact[(link.company_id, link.asset_id)] = link
                if semantic_key:
                    seen_semantic[semantic_key] = link
            else:
                self._merge_link(existing, link)
            removed += 1
        if removed:
            self.session.commit()
        return DedupeResult(task_id=task_id, removed_links=removed)

    def _semantic_key(self, link: CompanyAssetLink, asset: InternetAsset | None) -> tuple[int, str, str] | None:
        if not asset:
            return None
        if asset.asset_type in {"icp_domain", "subdomain", "ip", "email"}:
            value = _norm(asset.normalized_identifier)
        else:
            value = _norm(asset.display_name) or _norm(asset.normalized_identifier)
        if not value:
            return None
        return link.company_id, asset.asset_type, value

    def _asset_quality(self, asset: InternetAsset | None) -> int:
        if not asset:
            return 0
        value = _norm(asset.normalized_identifier)
        display = _norm(asset.display_name)
        if not value:
            return 0
        if asset.asset_type in {"icp_domain", "subdomain", "ip", "email"}:
            return 100
        if "icp" in value or "备案" in value:
            return 90
        if value.startswith(("gh_", "wx")):
            return 80
        if "." in value:
            return 70
        if value != display and not value.isdigit():
            return 60
        if value.isdigit():
            return 20
        return 10

    def _merge_link(self, existing: CompanyAssetLink, duplicate: CompanyAssetLink) -> None:
        payload = {**(existing.raw_payload or {})}
        sources = payload.get("sources") or [existing.source_tool]
        sources = list(sources)
        if duplicate.source_tool not in sources:
            sources.append(duplicate.source_tool)
        payload["sources"] = sources
        evidence = list(payload.get("evidence") or [{"source": existing.source_tool, "raw": existing.raw_payload}])
        evidence.append({"source": duplicate.source_tool, "raw": duplicate.raw_payload})
        payload["evidence"] = evidence
        existing.raw_payload = payload
        self.session.add(existing)
        self.session.delete(duplicate)
