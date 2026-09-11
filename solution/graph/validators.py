"""P2.3 完整性校验器：schema 校验 + 引用完整性 + 双源对账 + 悬空引用转风险项。

三类检查（对齐《资产识别实施计划》2.3）：
  SCH  schema 校验        —— 节点闭集/必填字段/边类型（jsonschema，计划 2.1 的声明式形态）
  REF  引用完整性          —— Tool 必有宿主 / 路由端点必须存在 / allowed-tools 可解析 /
                              MCP 至少暴露一工具 / 组件必须挂网络
  SRC  双源对账            —— compose 服务集合 vs 图节点集合，差集即漏报/孤儿清单
违规项产出与采集期同构的 finding（source=validator），可直接进 /api/risks。
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from graph.store import GraphStore

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"

COMPONENT_TYPES = {"AgentApplication", "AgentFlow", "FrameworkComponent",
                   "ModelEndpoint", "MCPServer", "DataStore", "ExternalEndpoint",
                   "Tool", "Skill", "SkillScript", "WebPage", "ConfigItem"}


def _f(rule, target, evidence, detail, tag, severity):
    return {"rule": rule, "target": target, "evidence": evidence, "detail": detail,
            "tag": tag, "severity": severity, "source": "validator"}


def validate_schema(gs: GraphStore) -> list[dict]:
    """节点/边 JSON Schema 校验（计划 2.1 声明式闭集）。"""
    node_schema = json.loads((SCHEMA_DIR / "nodes.schema.json").read_text(encoding="utf-8"))
    edge_schema = json.loads((SCHEMA_DIR / "edges.schema.json").read_text(encoding="utf-8"))
    findings = []
    for nid, attrs in gs.g.nodes(data=True):
        try:
            jsonschema.validate(attrs, node_schema)
        except jsonschema.ValidationError as e:
            findings.append(_f(
                "SCH-node-schema", nid, str(e.message)[:120],
                f"节点属性违反 schema：{e.message[:120]}", "CWE-1163", "medium"))
    for s, t, e in gs.g.edges(data=True):
        try:
            jsonschema.validate(e, edge_schema)
        except jsonschema.ValidationError as ex:
            findings.append(_f(
                "SCH-edge-schema", f"{s} -> {t}", str(ex.message)[:120],
                f"边属性违反 schema：{ex.message[:120]}", "CWE-1163", "medium"))
    return findings


def validate_references(gs: GraphStore) -> list[dict]:
    findings = []

    # REF-01 Tool 必有宿主 MCPServer
    for nid in gs.nodes_by_type("Tool"):
        if not gs.neighbors_in(nid, "exposes"):
            findings.append(_f(
                "REF-tool-without-host", nid, "无 exposes 入边",
                "Tool 节点没有宿主 MCPServer —— 孤立工具", "CWE-1163", "medium"))

    # REF-02 路由映射端必须存在（OPENAI_TOOL_ROUTES -> tool 节点）
    for agent in gs.nodes_by_type("AgentApplication"):
        routes = gs.g.nodes[agent]["declared"].get("routes") or {}
        for openai_name, endpoint in routes.items():
            server, tool_name = endpoint[0], endpoint[1]
            if f"tool:{server}.{tool_name}" not in gs.g:
                findings.append(_f(
                    "REF-route-endpoint-missing", f"route:{openai_name}",
                    f"agent={agent} 声明路由 -> {server}.{tool_name}",
                    "应用路由表指向的 (server, tool) 在图中不存在", "CWE-1163", "medium"))

    # REF-03 Skill allowed-tools 引用必须可解析（build 期记录的悬空引用）
    for nid in gs.nodes_by_type("Skill"):
        dangling = gs.g.nodes[nid]["declared"].get("dangling_allowed_tools") or []
        for target in dangling:
            findings.append(_f(
                "REF-allowed-tools-unresolved", nid,
                f"allowed-tools 引用 {target}",
                f"Skill {gs.g.nodes[nid]['name']} 的 allowed-tools 引用无法解析"
                f"（悬空引用）", "CWE-1163", "medium"))

    # REF-04 MCPServer 至少暴露一个工具
    for nid in gs.nodes_by_type("MCPServer"):
        if not gs.neighbors_out(nid, "exposes"):
            findings.append(_f(
                "REF-mcp-without-tools", nid, "exposes 出边为空",
                "MCP server 未暴露任何工具 —— 采集不全或空壳服务", "CWE-1163", "info"))

    # REF-05 部署组件必须挂网络（Tool 经宿主 server 继承、AgentFlow 经编排框架部署，不适用）
    for nid, d in gs.g.nodes(data=True):
        if d["type"] in {"AgentApplication", "FrameworkComponent", "ModelEndpoint",
                         "MCPServer", "DataStore", "ExternalEndpoint"}:
            if not gs.neighbors_out(nid, "attached_to"):
                findings.append(_f(
                    "REF-component-without-network", nid, "无 attached_to 出边",
                    "部署组件未关联任何网络分区", "CWE-1163", "info"))
    return findings


def validate_dual_source(gs: GraphStore, scan: dict) -> list[dict]:
    """compose 服务集合 vs 图节点集合：差集 = 漏报清单；反向 = 孤儿节点。"""
    findings = []
    compose = scan.get("compose") or {}
    services = {s["name"] for s in compose.get("services", [])}

    # 图中节点声称对应的 compose 服务
    represented = set()
    for nid, d in gs.g.nodes(data=True):
        svc = d.get("declared", {}).get("service") or (
            nid.split(":", 1)[-1] if d["type"] in
            {"MCPServer", "FrameworkComponent", "ModelEndpoint", "DataStore",
             "ExternalEndpoint", "AgentApplication"} and nid.split(":", 1)[-1] in services
            else None)
        if svc:
            represented.add(svc)

    for svc in sorted(services - represented):
        findings.append(_f(
            "SRC-compose-service-missing", svc, f"compose 声明 {svc}，图中无对应节点",
            "compose 服务未入图 —— 采集漏报清单", "CWE-1163", "medium"))
    for svc in sorted(represented - services):
        findings.append(_f(
            "SRC-orphan-node", svc, f"图节点声称服务 {svc}，compose 无此服务",
            "孤儿节点：图中资产在 compose 声明面中不存在", "CWE-1163", "info"))
    return findings


def run_validators(gs: GraphStore, scan: dict | None = None) -> dict:
    findings = validate_schema(gs) + validate_references(gs)
    if scan:
        findings += validate_dual_source(gs, scan)
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    return {"findings": findings, "total": len(findings), "by_rule": by_rule}


if __name__ == "__main__":
    import sys
    base = Path(__file__).resolve().parent.parent / "out"
    gs = GraphStore.load(base / "graph.json")
    scan = json.loads((base / "scan.json").read_text(encoding="utf-8"))
    result = run_validators(gs, scan)
    print(f"[validators] 发现 {result['total']} 项: {result['by_rule'] or '全部通过'}")
    for f in result["findings"][:10]:
        print(f"  [{f['severity']}] {f['rule']:<32} {f['target']}: {f['detail'][:60]}")
