"""图 -> 前端 JSON 导出（节点样式提示 + 边类型）。"""

from __future__ import annotations

from graph.store import GraphStore

TYPE_COLORS = {
    "AgentApplication": "#2563eb", "AgentFlow": "#60a5fa",
    "FrameworkComponent": "#7c3aed", "ModelEndpoint": "#06b6d4",
    "MCPServer": "#0d9488", "Tool": "#f59e0b",
    "Skill": "#10b981", "SkillScript": "#047857",
    "Identity": "#eab308", "DataStore": "#92400e",
    "NetworkSegment": "#6b7280", "ExternalEndpoint": "#ef4444",
    "WebPage": "#64748b", "ConfigItem": "#ec4899",
    "Package": "#5ad7e0",
}

TYPE_NAMES_ZH = {
    "AgentApplication": "Agent 应用", "AgentFlow": "编排 Flow",
    "FrameworkComponent": "框架组件", "ModelEndpoint": "模型端点",
    "MCPServer": "MCP 服务", "Tool": "工具",
    "Skill": "技能", "SkillScript": "技能脚本",
    "Identity": "身份", "DataStore": "数据存储",
    "NetworkSegment": "网络分区", "ExternalEndpoint": "外部端点",
    "WebPage": "网页内容", "ConfigItem": "配置项",
    "Package": "依赖包",
}


def export_for_frontend(gs: GraphStore) -> dict:
    nodes = []
    for nid, d in gs.g.nodes(data=True):
        ntype = d.get("type", "Unknown")
        nodes.append({
            "id": nid,
            "name": d.get("name", nid),
            "type": ntype,
            "type_zh": TYPE_NAMES_ZH.get(ntype, ntype),
            "color": TYPE_COLORS.get(ntype, "#94a3b8"),
            "severity": d.get("severity"),
            "risks": d.get("risks", []),
            "tier": d["declared"].get("tier"),
            "hidden": bool(d["declared"].get("hidden")),
            "score": d.get("bom_score"),
            "quadrant": d.get("bom_quadrant"),
            "autonomy": d.get("bom_autonomy"),
            "declared": d.get("declared", {}),
            "observed": d.get("observed", {}),
            "provenance": d.get("provenance", []),
        })
    edges = []
    for i, (s, t, e) in enumerate(gs.g.edges(data=True)):
        edges.append({"id": f"e{i}", "source": s, "target": t,
                      "etype": e.get("etype", "rel"),
                      "declared": e.get("declared", True)})
    return {"nodes": nodes, "edges": edges,
            "meta": {"node_count": len(nodes), "edge_count": len(edges),
                     "types": {t: TYPE_NAMES_ZH.get(t, t) for t in
                               sorted({n["type"] for n in nodes})}}}
