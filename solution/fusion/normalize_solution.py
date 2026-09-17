"""把 solution 图谱、BOM 与四路发现归一化为 canonical 结构。"""

from __future__ import annotations

from typing import Any

from .ids import normalize_path, slug
from .models import CanonicalAsset, CanonicalEdge, CanonicalRisk, NormalizedResult


def normalize_solution(artifacts: dict[str, Any]) -> NormalizedResult:
    graph = artifacts.get("graph_enriched") or artifacts.get("graph") or {}
    assets = []
    for node in graph.get("nodes", []):
        nid = node["id"]
        assets.append(CanonicalAsset(
            id=nid,
            type=node.get("type", "Unknown"),
            name=node.get("name", nid),
            declared=dict(node.get("declared") or {}),
            observed=dict(node.get("observed") or {}),
            provenance=list(node.get("provenance") or []),
            source_ids=[nid], sources=["solution"], native=dict(node),
            attrs={key: node[key] for key in (
                "severity", "risks", "bom_score", "bom_quadrant", "bom_autonomy",
            ) if key in node},
        ))

    edges = []
    for index, edge in enumerate(graph.get("edges") or graph.get("links", [])):
        attrs = {key: value for key, value in edge.items()
                 if key not in {"source", "target", "etype", "declared", "observed", "provenance", "id"}}
        edges.append(CanonicalEdge(
            id=edge.get("id", f"solution:e{index}"), source=edge["source"], target=edge["target"],
            relation=edge.get("etype", "related_to"), declared=edge.get("declared", True),
            observed=edge.get("observed"), attrs=attrs,
            provenance=list(edge.get("provenance") or []), sources=["solution"],
        ))

    risks = []
    known_ids = {asset.id for asset in assets}
    for source_kind, rows in _risk_sources(artifacts):
        for index, row in enumerate(rows):
            rule = str(row.get("rule") or row.get("id") or f"{source_kind}-{index}")
            target = str(row.get("target") or row.get("asset_id") or "")
            asset_id = row.get("asset_id") or _resolve_target(target, assets)
            if asset_id not in known_ids:
                asset_id = f"unknown:risk-target:{source_kind}:{index}"
                assets.append(CanonicalAsset(
                    id=asset_id, type="Unknown", name=target or rule,
                    confidence=0.0, attrs={"synthetic": True, "original_target": target},
                    provenance=[{"source": "solution", "kind": source_kind}],
                    source_ids=[asset_id], sources=["solution"],
                ))
                known_ids.add(asset_id)
            evidence = _evidence(row.get("evidence"), rule)
            risks.append(CanonicalRisk(
                id=f"solution:{source_kind}:{rule}:{index}", asset_id=asset_id,
                category=row.get("category") or _category(source_kind, row),
                severity=row.get("severity", "info"), title=row.get("title") or rule,
                description=row.get("description") or row.get("detail") or "",
                evidence=evidence, related_asset_ids=list(row.get("related_asset_ids") or []),
                malicious_type=row.get("malicious_type"), confidence=float(row.get("confidence", 1.0)),
                source="solution", source_kind=source_kind, rule=rule, target=target,
                tag=row.get("tag", ""), native_ids=[str(row.get("id") or rule)],
            ))
    return NormalizedResult(assets=assets, edges=edges, risks=risks,
                            aliases={asset.id: asset.id for asset in assets},
                            quality={"source": "solution", "dropped_edges": [], "unresolved_risks": []})


def _risk_sources(artifacts: dict[str, Any]):
    yield "static", (artifacts.get("scan") or {}).get("risks", [])
    yield "envelope", _findings(artifacts.get("envelope"))
    yield "runtime", _findings(artifacts.get("runtime") or artifacts.get("runtime_runtime_findings"))
    yield "validator", _findings(artifacts.get("validator") or artifacts.get("validator_findings"))


def _findings(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return value
    return value.get("findings", []) if isinstance(value, dict) else []


def _resolve_target(target: str, assets: list[CanonicalAsset]) -> str:
    ids = {asset.id for asset in assets}
    if target in ids:
        return target
    tokens = [token.strip() for token in target.split("->")]
    exact = [token for token in tokens if token in ids]
    if exact:
        return exact[0]

    prefix_map = {"route": "AgentApplication", "cfg": "ConfigItem", "mcp": "MCPServer",
                  "skill": "Skill", "tool": "Tool", "agent": "AgentApplication"}
    prefix, separator, value = target.partition(":")
    wanted_type = prefix_map.get(prefix) if separator else None
    wanted_name = slug(value if separator else target)
    named = [asset.id for asset in assets
             if (not wanted_type or asset.type == wanted_type) and slug(asset.name) == wanted_name]
    if len(named) == 1:
        return named[0]
    if prefix == "route":
        agents = [asset.id for asset in assets if asset.type == "AgentApplication"]
        if len(agents) == 1:
            return agents[0]

    target_path = normalize_path(target)
    by_path = []
    for asset in assets:
        candidates = [asset.path, (asset.declared or {}).get("path")]
        if any(normalize_path(candidate) == target_path for candidate in candidates if candidate):
            by_path.append(asset.id)
    if len(by_path) == 1:
        return by_path[0]

    image_name = target.split("/", 1)[-1].split(":", 1)[0] if "/" in target else ""
    if image_name:
        image_hits = [asset.id for asset in assets if slug(asset.name) == slug(image_name)]
        if len(image_hits) == 1:
            return image_hits[0]

    candidates = [asset.id for asset in assets if target.startswith(asset.id) or asset.id in target]
    return candidates[0] if candidates else ""


def _evidence(value: Any, rule: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item if isinstance(item, dict) else {"rule_id": rule, "snippet": str(item)} for item in value]
    if isinstance(value, dict):
        return [value]
    return [{"rule_id": rule, "file": str(value)}] if value else []


def _category(source_kind: str, row: dict[str, Any]) -> str:
    if source_kind == "runtime":
        return "runtime_anomaly"
    if source_kind == "validator":
        return "integrity"
    return "finding"
