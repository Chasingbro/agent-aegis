"""确定性合并 canonical 图谱并保留双方证据与别名。"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .ids import slug
from .models import CanonicalAsset, CanonicalEdge, CanonicalRisk, NormalizedResult

_COMPATIBLE_TYPES = {
    "Service": {"AgentApplication", "FrameworkComponent", "ModelEndpoint", "DataStore",
                "ExternalEndpoint", "MCPServer"},
    "FrameworkComponent": {"FrameworkComponent", "ModelEndpoint"},
}


def merge_results(solution: NormalizedResult, peer: NormalizedResult) -> NormalizedResult:
    assets: dict[str, CanonicalAsset] = {asset.id: deepcopy(asset) for asset in solution.assets}
    aliases = dict(solution.aliases)
    peer_canonical_map: dict[str, str] = {}

    for incoming in peer.assets:
        target = _asset_target(incoming, assets)
        if target:
            _merge_asset(assets[target], incoming)
            canonical = target
        else:
            canonical = incoming.id
            if canonical in assets:
                canonical = _disambiguate(canonical, incoming.type, assets)
            clone = deepcopy(incoming)
            clone.id = canonical
            assets[canonical] = clone
        peer_canonical_map[incoming.id] = canonical
        aliases[incoming.id] = canonical
        for source_id in incoming.source_ids:
            aliases[source_id] = canonical

    edges: dict[tuple[str, str, str], CanonicalEdge] = {}
    dropped_edges = []
    for edge in [*solution.edges, *peer.edges]:
        source = _remap(edge.source, aliases, peer_canonical_map)
        target = _remap(edge.target, aliases, peer_canonical_map)
        if source not in assets or target not in assets:
            dropped_edges.append({"edge_id": edge.id, "source": edge.source,
                                  "target": edge.target, "reason": "unresolved_after_merge"})
            continue
        key = (source, target, edge.relation)
        if key not in edges:
            clone = deepcopy(edge)
            clone.source, clone.target = source, target
            clone.id = f"edge:{len(edges)}"
            edges[key] = clone
        else:
            _merge_edge(edges[key], edge)

    risks: dict[tuple[str, str], CanonicalRisk] = {}
    unresolved_risks = []
    for risk in [*solution.risks, *peer.risks]:
        clone = deepcopy(risk)
        clone.asset_id = _remap(clone.asset_id, aliases, peer_canonical_map)
        clone.related_asset_ids = list(dict.fromkeys(
            _remap(value, aliases, peer_canonical_map) for value in clone.related_asset_ids
            if _remap(value, aliases, peer_canonical_map)
        ))
        if clone.asset_id not in assets:
            unresolved_risks.append({"risk_id": clone.id, "asset_id": clone.asset_id,
                                     "reason": "unresolved_after_merge"})
        key = (clone.source, clone.id)
        if key not in risks:
            risks[key] = clone
        else:
            _merge_risk(risks[key], clone)

    all_dropped_edges = [*(peer.quality.get("dropped_edges") or []), *dropped_edges]
    all_unresolved_risks = [*(peer.quality.get("unresolved_risks") or []), *unresolved_risks]
    quality = {
        "peer": peer.quality,
        "solution": solution.quality,
        "dropped_edges": all_dropped_edges,
        "unresolved_risks": all_unresolved_risks,
        "invariants": {
            "all_edge_endpoints_resolved": not all_dropped_edges,
            "all_risk_targets_resolved": not all_unresolved_risks,
        },
    }
    return NormalizedResult(assets=list(assets.values()), edges=list(edges.values()),
                            risks=list(risks.values()), aliases=aliases, quality=quality)


def _asset_target(incoming: CanonicalAsset, assets: dict[str, CanonicalAsset]) -> str | None:
    if incoming.id in assets:
        return incoming.id
    name = slug(incoming.name)
    matches = []
    compatible = _COMPATIBLE_TYPES.get(incoming.type, {incoming.type})
    for asset in assets.values():
        if asset.type in compatible and slug(asset.name) == name:
            matches.append(asset.id)
    return matches[0] if len(matches) == 1 else None


def _merge_asset(current: CanonicalAsset, incoming: CanonicalAsset) -> None:
    current.confidence = max(current.confidence, incoming.confidence)
    current.path = current.path or incoming.path
    current.declared.update(incoming.declared)
    current.observed.update(incoming.observed)
    current.attrs.update(incoming.attrs)
    _extend_unique(current.evidence, incoming.evidence)
    _extend_unique(current.provenance, incoming.provenance)
    _extend_unique(current.source_ids, [incoming.id, *incoming.source_ids])
    _extend_unique(current.sources, incoming.sources)
    if incoming.native:
        current.native.setdefault("source_records", {})[incoming.sources[0]] = incoming.native


def _merge_edge(current: CanonicalEdge, incoming: CanonicalEdge) -> None:
    current.attrs.update(incoming.attrs)
    _extend_unique(current.provenance, incoming.provenance)
    _extend_unique(current.sources, incoming.sources)
    current.observed = current.observed or incoming.observed


def _merge_risk(current: CanonicalRisk, incoming: CanonicalRisk) -> None:
    _extend_unique(current.evidence, incoming.evidence)
    _extend_unique(current.related_asset_ids, incoming.related_asset_ids)
    _extend_unique(current.native_ids, incoming.native_ids)
    current.confidence = max(current.confidence, incoming.confidence)


def _extend_unique(target: list, values: list) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def _remap(value: str, aliases: dict[str, str], local: dict[str, str]) -> str:
    return local.get(value) or aliases.get(value) or value


def _disambiguate(base: str, asset_type: str, assets: dict[str, Any]) -> str:
    candidate = f"{base}#{slug(asset_type)}"
    index = 2
    while candidate in assets:
        candidate = f"{base}#{slug(asset_type)}-{index}"
        index += 1
    return candidate
