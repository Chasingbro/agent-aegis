"""P1 canonical 合并、严格读取和脱敏回归。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SOLUTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOLUTION))


def _solution_artifacts():
    return {
        "graph": {
            "nodes": [
                {"id": "agent:app", "type": "AgentApplication", "name": "app",
                 "declared": {}, "observed": {}, "provenance": ["app.py"]},
                {"id": "mcp:notes-sync", "type": "MCPServer", "name": "notes-sync",
                 "declared": {}, "observed": {}, "provenance": ["mcp.py"]},
                {"id": "tool:notes-sync.sync_note", "type": "Tool", "name": "sync_note",
                 "declared": {}, "observed": {}, "provenance": ["mcp.py"]},
                {"id": "cfg:JWT_SECRET", "type": "ConfigItem", "name": "JWT_SECRET",
                 "declared": {"value": "change-me-weak-secret"}, "observed": {},
                 "provenance": [".env"]},
            ],
            "edges": [{"source": "mcp:notes-sync", "target": "tool:notes-sync.sync_note",
                       "etype": "exposes", "route": "notes_sync_sync_note"}],
        },
        "scan": {"root": "target", "risks": [
            {"rule": "weak-secret", "target": "JWT_SECRET", "severity": "high",
             "detail": "JWT_SECRET 使用 change-me-weak-secret", "evidence": ".env"}
        ]},
    }


def _peer_payload():
    return {
        "assets": [
            {"id": "mcp_server:notes-sync", "type": "mcp_server", "name": "notes-sync",
             "path": "mcp/notes_sync/server.py", "confidence": 0.9, "evidence": [], "attrs": {}},
            {"id": "mcp_tool:notes-sync:sync-note", "type": "mcp_tool", "name": "sync_note",
             "path": "mcp/notes_sync/server.py", "confidence": 0.9, "evidence": [],
             "attrs": {"server": "notes-sync"}},
            {"id": "package:fastapi", "type": "package", "name": "fastapi",
             "path": "requirements.txt", "confidence": 0.85, "evidence": [], "attrs": {}},
        ],
        "nodes": [{"id": "endpoint:only-graph", "type": "endpoint", "name": "host:1234",
                   "path": "compose.yml", "confidence": 0.9}],
        "edges": [
            {"src": "mcp_server:notes-sync", "dst": "mcp_tool:notes-sync:sync-note",
             "relation": "provides"},
            {"src": "mcp_server:notes-sync", "dst": "endpoint:only-graph",
             "relation": "exposes"},
        ],
        "risks": [{"id": "peer-risk", "asset_id": "mcp_server:notes-sync",
                   "category": "malicious_mcp", "severity": "high", "title": "投毒",
                   "description": "TOKEN=plain-peer-secret", "confidence": 0.9,
                   "evidence": [{"rule_id": "x", "file": "mcp.py",
                                 "snippet": "TOKEN=plain-peer-secret"}],
                   "related_asset_ids": ["mcp_tool:notes-sync:sync-note"]}],
        "bench": {"available": False, "reason": "fixture"},
        "peer_scan": {"status": "ready"},
    }


def test_graph_only_node_alias_risk_and_edge_merge():
    from fusion.payload import build_dashboard_payload

    payload = build_dashboard_payload(_solution_artifacts(), _peer_payload())
    ids = {asset["id"] for asset in payload["assets"]}
    assert "endpoint:host-1234" in ids
    assert payload["id_aliases"]["mcp_server:notes-sync"] == "mcp:notes-sync"
    assert payload["id_aliases"]["mcp_tool:notes-sync:sync-note"] == "tool:notes-sync.sync_note"
    peer_risk = next(risk for risk in payload["risks"] if risk["source"] == "agent-scanner")
    assert peer_risk["asset_id"] == "mcp:notes-sync"
    assert peer_risk["related_asset_ids"] == ["tool:notes-sync.sync_note"]
    assert payload["quality"]["peer"]["inferred_nodes"] == 1
    assert payload["quality"]["invariants"] == {
        "all_edge_endpoints_resolved": True,
        "all_risk_targets_resolved": True,
    }


def test_unresolved_peer_edge_is_reported_not_silent():
    from fusion.normalize_peer import normalize_peer
    from fusion.normalize_solution import normalize_solution
    from fusion.merge import merge_results

    peer = _peer_payload()
    peer["edges"].append({"src": "missing", "dst": "package:fastapi", "relation": "uses"})
    fused = merge_results(normalize_solution(_solution_artifacts()), normalize_peer(peer))
    assert not fused.quality["invariants"]["all_edge_endpoints_resolved"]
    assert fused.quality["dropped_edges"][0]["reason"] == "unresolved_endpoint"


def test_two_pass_redaction_covers_generic_value_and_risk_text():
    from fusion.payload import build_dashboard_payload

    payload = build_dashboard_payload(_solution_artifacts(), _peer_payload())
    text = json.dumps(payload, ensure_ascii=False)
    assert "change-me-weak-secret" not in text
    assert "plain-peer-secret" not in text
    assert "[REDACTED]" in text
    config = next(asset for asset in payload["assets"] if asset["id"] == "cfg:JWT_SECRET")
    assert config["declared"]["value"] == "[REDACTED]"


def test_distinct_solution_risks_are_not_collapsed():
    from fusion.payload import build_dashboard_payload

    artifacts = _solution_artifacts()
    artifacts["scan"]["risks"].append({
        "rule": "known-version", "target": "agent:app", "severity": "high", "detail": "CVE-A"
    })
    artifacts["scan"]["risks"].append({
        "rule": "known-version", "target": "agent:app", "severity": "high", "detail": "CVE-B"
    })
    payload = build_dashboard_payload(artifacts)
    assert sum(risk["rule"] == "known-version" for risk in payload["risks"]) == 2
