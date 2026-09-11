"""BOM -> 图谱导入：按节点 id upsert，把 tier/autonomy/score/controls 回填为节点属性。

用途：① round-trip（图 -> BOM -> 图，验证零丢失）② 外部 BOM 合并（provenance 标注）
"""

from __future__ import annotations

from graph.store import GraphStore

BOM_PROV = "bom:import"


def import_bom(gs: GraphStore, bom: dict) -> dict:
    """把 BOM 工件导入图。返回统计 {agents, tools_matched, tools_created, attrs_set}。"""
    stats = {"agents": 0, "tools_matched": 0, "tools_created": 0, "attrs_set": 0}
    for agent in bom.get("agents", []):
        aid = agent["identity"]["id"]
        kind = agent["identity"].get("kind", "application")
        if aid not in gs.g:
            ntype = "AgentFlow" if kind == "flow" else "AgentApplication"
            gs.add_node(aid, ntype, agent["identity"]["name"],
                        declared={}, provenance=[f"{BOM_PROV}:external"])
            stats["agents"] += 1
        node = gs.g.nodes[aid]
        ra = agent.get("risk_assessment") or {}
        bom_attrs = {
            "bom_autonomy": agent["autonomy"]["level"],
            "bom_score": ra.get("score"),
            "bom_quadrant": ra.get("quadrant"),
            "bom_drivers": ra.get("drivers"),
            "bom_controls": [c["family"] for c in ra.get("controls", [])],
            "bom_weakness_kinds": [w["kind"] for w in
                                   agent.get("governance_weaknesses", [])],
            "bom_max_tier": ra.get("max_tool_tier"),
        }
        node.update(bom_attrs)
        stats["attrs_set"] += len(bom_attrs)
        if BOM_PROV not in node["provenance"]:
            node["provenance"].append(BOM_PROV)

        for tool in agent.get("tools", []):
            ref = tool["ref"]
            if ref not in gs.g:
                gs.add_node(ref, "Tool", tool["name"],
                            declared={"tier": tool["tier"],
                                      "tier_reason": tool["tier_reason"],
                                      "hidden": tool.get("hidden", False)},
                            provenance=[f"{BOM_PROV}:external"])
                stats["tools_created"] += 1
            else:
                tnode = gs.g.nodes[ref]
                tnode["declared"].update({
                    "tier": tool["tier"], "tier_reason": tool["tier_reason"]})
                if BOM_PROV not in tnode["provenance"]:
                    tnode["provenance"].append(BOM_PROV)
                stats["tools_matched"] += 1
            if not gs.g.has_edge(aid, ref):
                gs.add_edge(aid, ref, "mounts", route=None, declared=True,
                            provenance=BOM_PROV)
    return stats


def round_trip_check(original: GraphStore, bom: dict) -> dict:
    """验证：original -> BOM -> 重建图后，节点/边零丢失且 BOM 属性就位。"""
    rebuilt = GraphStore()
    rebuilt.g = original.g.copy()
    # 清除已有 bom 属性，模拟未导入状态
    for _, d in rebuilt.g.nodes(data=True):
        for k in list(d):
            if k.startswith("bom_"):
                del d[k]
    import_bom(rebuilt, bom)

    lost_nodes = set(original.g.nodes) - set(rebuilt.g.nodes)
    lost_edges = set(original.g.edges) - set(rebuilt.g.edges)
    agent_ids = [a["identity"]["id"] for a in bom["agents"]]
    agents_ok = all("bom_score" in rebuilt.g.nodes[a] for a in agent_ids)
    tiers_ok = all(
        "tier" in rebuilt.g.nodes[t["ref"]]["declared"]
        for a in bom["agents"] for t in a["tools"] if t["ref"] in rebuilt.g)
    return {"lost_nodes": sorted(lost_nodes), "lost_edges": sorted(lost_edges),
            "agents_attributed": agents_ok, "tools_tiered": tiers_ok,
            "pass": not lost_nodes and not lost_edges and agents_ok and tiers_ok}


if __name__ == "__main__":
    import sys
    from pathlib import Path
    from bom.schema import load_bom
    gs = GraphStore.load(Path(sys.argv[1] if len(sys.argv) > 1 else "out/graph.json"))
    bom = load_bom(sys.argv[2] if len(sys.argv) > 2 else "out/bom.json")
    stats = import_bom(gs, bom)
    result = round_trip_check(gs, bom)
    print("import stats:", stats)
    print("round-trip:", result)
    gs.save(Path("out/graph.enriched.json"))
    print("enriched graph -> out/graph.enriched.json")
