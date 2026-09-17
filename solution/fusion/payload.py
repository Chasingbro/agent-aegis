"""构建队友前端兼容、同时保留 solution facets 的融合 dashboard payload。"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .merge import merge_results
from .normalize_peer import normalize_peer
from .normalize_solution import normalize_solution
from .redact import redact_document

SCHEMA_VERSION = "fusion-dashboard-v1"
TYPE_META = {
    "AgentApplication": ("agent", "Agent 应用", "#2563eb"),
    "AgentFlow": ("agent_flow", "编排 Flow", "#60a5fa"),
    "FrameworkComponent": ("framework", "推理框架", "#7c3aed"),
    "ModelEndpoint": ("model", "模型", "#06b6d4"),
    "MCPServer": ("mcp_server", "MCP 服务", "#0d9488"),
    "Tool": ("mcp_tool", "MCP 工具", "#f59e0b"),
    "Skill": ("skill", "Skill", "#10b981"),
    "SkillScript": ("script", "技能脚本", "#047857"),
    "Identity": ("identity", "身份", "#eab308"),
    "DataStore": ("data_store", "数据存储", "#92400e"),
    "NetworkSegment": ("network", "网络分区", "#6b7280"),
    "ExternalEndpoint": ("external_endpoint", "外部端点", "#ef4444"),
    "Endpoint": ("endpoint", "端口端点", "#69d9d0"),
    "WebPage": ("web_page", "网页内容", "#64748b"),
    "ConfigItem": ("config", "配置", "#ec4899"),
    "Package": ("package", "依赖包", "#5ad7e0"),
    "Credential": ("credential", "凭据", "#c9a227"),
    "Service": ("service", "服务", "#9aa7bd"),
    "Unknown": ("unknown", "未归属", "#7f8c9b"),
}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0, None: -1}


def build_dashboard_payload(
    artifacts: dict[str, Any],
    peer_payload: dict[str, Any] | None = None,
    *,
    peer_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    solution = normalize_solution(artifacts)
    peer = normalize_peer(peer_payload or {})
    fused = merge_results(solution, peer)
    risk_index = _risk_index(fused.risks)
    degree = Counter()
    for edge in fused.edges:
        degree[edge.source] += 1
        degree[edge.target] += 1

    assets = [_asset_row(asset, risk_index.get(asset.id, []), degree[asset.id])
              for asset in fused.assets]
    edges = [_edge_row(edge) for edge in fused.edges]
    risks = [_risk_row(risk) for risk in fused.risks]
    summary = {
        "asset_counts": dict(Counter(asset["type"] for asset in assets)),
        "risk_counts_by_severity": dict(Counter(risk["severity"] for risk in risks)),
        "risk_counts_by_category": dict(Counter(risk["category"] for risk in risks)),
        "risk_counts_by_source": dict(Counter(risk["source"] for risk in risks)),
        "graph_nodes": len(assets), "graph_edges": len(edges), "risk_count": len(risks),
    }
    payload = {
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": (artifacts.get("scan") or {}).get("root", ""),
            "source_engines": ["solution"] + (["agent-scanner"] if peer.assets else []),
        },
        "summary": summary, "assets": assets, "nodes": assets, "edges": edges,
        "risks": risks, "bench": (peer_payload or {}).get("bench", {}),
        "facets": {
            "declared": {asset["id"]: asset["declared"] for asset in assets},
            "observed": {asset["id"]: asset["observed"] for asset in assets},
            "bom": {asset["id"]: asset["bom"] for asset in assets if asset["bom"]},
            "provenance": {asset["id"]: asset["provenance"] for asset in assets},
        },
        "runtime": artifacts.get("runtime") or artifacts.get("runtime_runtime_findings") or {},
        "baseline": artifacts.get("baseline") or {},
        "id_aliases": fused.aliases,
        "quality": fused.quality,
        "peer_scan": peer_status or (peer_payload or {}).get("peer_scan", {"status": "not_run"}),
        "peer_load": (peer_payload or {}).get("peer_load", {}),
        "source_engines": {
            "solution": {"nodes": len(solution.assets), "edges": len(solution.edges),
                         "risks": len(solution.risks)},
            "agent-scanner": {"nodes": len(peer.assets), "edges": len(peer.edges),
                              "risks": len(peer.risks)},
        },
    }
    return redact_document(payload)


def _risk_index(risks):
    index = {}
    for risk in risks:
        for asset_id in [risk.asset_id, *risk.related_asset_ids]:
            index.setdefault(asset_id, []).append(risk)
    return index


def _asset_row(asset, risks, degree):
    frontend_type, type_zh, color = TYPE_META.get(asset.type, (asset.type, asset.type, "#94a3b8"))
    severities = [risk.severity for risk in risks]
    severity = max(severities, key=lambda value: SEVERITY_RANK.get(value, -1)) if severities else None
    bom = {key.removeprefix("bom_"): value for key, value in asset.attrs.items()
           if key.startswith("bom_")}
    return {
        "id": asset.id, "type": frontend_type, "canonical_type": asset.type,
        "type_zh": type_zh, "color": color, "name": asset.name, "path": asset.path,
        "confidence": asset.confidence, "degree": degree, "risk_count": len(risks),
        "max_severity": severity, "severity": severity,
        "declared": asset.declared, "observed": asset.observed, "attrs": asset.attrs,
        "evidence": asset.evidence, "provenance": asset.provenance,
        "source_ids": asset.source_ids, "sources": asset.sources, "bom": bom,
        "tier": asset.declared.get("tier"), "hidden": bool(asset.declared.get("hidden")),
        "score": asset.attrs.get("bom_score"), "quadrant": asset.attrs.get("bom_quadrant"),
        "autonomy": asset.attrs.get("bom_autonomy"),
        "risks": [risk.id for risk in risks],
    }


def _edge_row(edge):
    return {"id": edge.id, "src": edge.source, "dst": edge.target,
            "source": edge.source, "target": edge.target,
            "relation": edge.relation, "etype": edge.relation,
            "declared": edge.declared, "observed": edge.observed,
            "attrs": edge.attrs, "provenance": edge.provenance, "sources": edge.sources}


def _risk_row(risk):
    return {"id": risk.id, "asset_id": risk.asset_id, "category": risk.category,
            "severity": risk.severity, "title": risk.title, "description": risk.description,
            "evidence": risk.evidence, "related_asset_ids": risk.related_asset_ids,
            "malicious_type": risk.malicious_type, "confidence": risk.confidence,
            "source": risk.source, "source_kind": risk.source_kind, "rule": risk.rule,
            "target": risk.target, "tag": risk.tag, "native_ids": risk.native_ids}
