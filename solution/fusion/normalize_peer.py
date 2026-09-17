"""把 agent-scanner payload 归一化，补 graph-only 节点并记录质量问题。"""

from __future__ import annotations

from typing import Any

from .ids import PEER_RELATION_MAP, PEER_TYPE_MAP, canonical_peer_id
from .models import CanonicalAsset, CanonicalEdge, CanonicalRisk, NormalizedResult


def normalize_peer(payload: dict[str, Any]) -> NormalizedResult:
    raw_assets = list(payload.get("assets") or [])
    known_native = {asset.get("id") for asset in raw_assets if isinstance(asset, dict)}
    inferred = []
    for node in payload.get("nodes") or []:
        if isinstance(node, dict) and node.get("id") not in known_native:
            inferred.append({**node, "attrs": {**(node.get("attrs") or {}),
                                                "inferred_from": "graph.json"},
                             "confidence": min(float(node.get("confidence", 0.5)), 0.5),
                             "evidence": node.get("evidence") or []})
    raw_assets.extend(inferred)

    aliases: dict[str, str] = {}
    assets = []
    for item in raw_assets:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        canonical = canonical_peer_id(item)
        aliases[item["id"]] = canonical
        assets.append(CanonicalAsset(
            id=canonical, type=PEER_TYPE_MAP.get(item.get("type", "unknown"), "Unknown"),
            name=item.get("name", canonical), path=item.get("path", ""),
            confidence=float(item.get("confidence", 1.0)), attrs=dict(item.get("attrs") or {}),
            evidence=[dict(value) for value in item.get("evidence", []) if isinstance(value, dict)],
            provenance=[{"source": "agent-scanner", "evidence": value}
                        for value in item.get("evidence", []) if isinstance(value, dict)],
            source_ids=[item["id"]], sources=["agent-scanner"], native=dict(item),
        ))

    edges = []
    dropped_edges = []
    for index, item in enumerate(payload.get("edges") or []):
        if not isinstance(item, dict):
            continue
        source = aliases.get(item.get("src") or item.get("source"))
        target = aliases.get(item.get("dst") or item.get("target"))
        if not source or not target:
            dropped_edges.append({"edge": item, "reason": "unresolved_endpoint"})
            continue
        relation = item.get("relation") or item.get("etype") or "related_to"
        edges.append(CanonicalEdge(
            id=f"agent-scanner:e{index}", source=source, target=target,
            relation=PEER_RELATION_MAP.get(relation, relation),
            attrs={"source_relation": relation}, provenance=[{"source": "agent-scanner"}],
            sources=["agent-scanner"],
        ))

    risks = []
    unresolved_risks = []
    for item in payload.get("risks") or []:
        if not isinstance(item, dict):
            continue
        asset_id = aliases.get(item.get("asset_id"))
        related = [aliases.get(value) for value in item.get("related_asset_ids", [])]
        if not asset_id:
            unresolved_risks.append({"risk_id": item.get("id"), "asset_id": item.get("asset_id")})
            asset_id = ""
        unresolved_related = [raw for raw, canonical in zip(item.get("related_asset_ids", []), related)
                              if not canonical]
        if unresolved_related:
            unresolved_risks.append({"risk_id": item.get("id"),
                                     "related_asset_ids": unresolved_related})
        risk_id = str(item.get("id") or "peer-risk")
        risks.append(CanonicalRisk(
            id=f"agent-scanner:{risk_id}", asset_id=asset_id,
            category=item.get("category", "finding"), severity=item.get("severity", "info"),
            title=item.get("title") or risk_id, description=item.get("description", ""),
            evidence=[dict(value) for value in item.get("evidence", []) if isinstance(value, dict)],
            related_asset_ids=[value for value in related if value],
            malicious_type=item.get("malicious_type"), confidence=float(item.get("confidence", 1.0)),
            source="agent-scanner", source_kind="static",
            rule=(item.get("evidence") or [{}])[0].get("rule_id", item.get("category", "finding")),
            target=item.get("asset_id", ""), native_ids=[risk_id],
        ))
    return NormalizedResult(
        assets=assets, edges=edges, risks=risks, aliases=aliases,
        quality={"source": "agent-scanner", "inferred_nodes": len(inferred),
                 "dropped_edges": dropped_edges, "unresolved_risks": unresolved_risks},
    )
